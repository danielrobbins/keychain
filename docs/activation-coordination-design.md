# Activation Coordination: Correctness Guide

This describes the lifetime-based coordination implementation, and is implemented in Keychain 3.0.5. It replaces the previous use of a saved `in_progress` flag and JSON waiter list to decide whether a terminal should wait. It does not change the SSH agent selection policy or add a daemon.

## The Problem Being Fixed

The previous implementation could save "loading", then die without clearing that record or notifying waiting terminals. The operating system correctly released its lock, but those terminals remained asleep waiting for a message that would never arrive. This was an indefinite wait, not necessarily two kernel locks deadlocking each other. Atomic JSON replacement protected the integrity of an individual write; it did not make the saved description of a process remain true after that process died.

A second problem was that only Keychain held the activation lock. Killing Keychain alone could leave its `ssh-add` child alive and prompting while another Keychain could acquire the lock. The replacement must protect the lifetime of the loading operation, not just its parent.

## The Participants

- A **waiting terminal** is a Keychain invocation that still needs its requested SSH keys.
- The **loading terminal** is the invocation that acquired the activation lock and is allowed to run `ssh-add`.
- `ssh-agent` remains the authority on which keys are actually loaded. Neither a notification nor a saved success result substitutes for checking the requested keys.

## Locks and Their Purpose

Keychain uses **two coordination locks**: the state lock and the activation lock. They answer different questions. The state lock controls who may perform a shared setup or coordination update right now. The activation lock controls who may run a key-loading operation. Both are enforced by the operating system; "OS lock" describes that mechanism, not a third lock.

The state file and FIFOs support those locks but do not replace them. A **FIFO**, also called a named pipe, is a communication channel that processes open through a filesystem path.

The **lifetime FIFO** wakes waiting terminals when a loading operation ends, even if the loading processes die without sending a completion message. The loading Keychain process and its `ssh-add` child keep it open for writing. Other terminals watch for the moment when no writer remains open. No messages are written to or read from this pipe; its closure tells them the operation has ended, not whether it succeeded.

Two other FIFOs carry actual messages: each waiting terminal's **notification FIFO** receives start and completion messages, and each loading attempt's **cancellation FIFO** receives takeover requests. The **state file** records the latest attempt and its status. The subsections below explain how these resources work with the locks, using terminals A and B as examples.

The resource labels use `paths` for the `KeychainPaths` instance, `waiter` for an `ActivationWaiter`, and `owner` for an `ActivationOwner`.

### OS Lock: How Ownership Is Enforced

**Purpose:** Have the operating system enforce exclusive ownership, so two Keychain invocations cannot independently acquire the same lock at the same time.

**Mechanism:** `fcntl.flock`, wrapped by `LockFile`. It is applied separately to the state-lock file and the activation-lock file.

Suppose terminal A acquires an OS lock on a file. Terminal B can see that file too, but it cannot acquire the same exclusive lock while A holds it. When A releases the lock, B can acquire it. The file can remain on disk throughout: its existence is not what makes the lock held or available.

An open file handle is called a **file descriptor** in the code. Keychain releases a lock by closing its holding descriptor. If a child inherited that descriptor, the lock remains held until the last holding descriptor closes. The operating system also closes a process's descriptors when it dies, even if Python cleanup never runs. Consequently, killing A releases its lock only if no surviving child still holds it. No saved JSON value decides this.

The state lock and activation lock use different files. Holding one does not automatically acquire the other. These locks coordinate Keychain invocations that use this protocol; they do not prevent a user from independently running `ssh-add`.

### State Lock: Keep Shared Setup and Updates Consistent

**Purpose:** Keep agent setup and shared coordination updates from interfering with one another when several Keychain invocations run at once.

**Resource:** `paths.state_lockf`, stored as `<host>.state.lock`.

Suppose terminals A and B start together and neither has an agent yet. Both first read the pidfile and check existing agent candidates without holding the state lock. A then acquires the lock and rereads the pidfile. If its socket/PID information has not changed, A can start an agent and write its pidfile before releasing the lock. When B acquires the lock, it sees that A changed the pidfile. B releases the lock, repeats its agent checks, and validates A's agent. It then reacquires the lock and rechecks the pidfile before accepting that selection. B does not start a duplicate agent based on its earlier observation.

This separation matters because even a healthy agent can delay answering a query while waiting for a graphical `--confirm` approval. Holding the state lock during that query would prevent other terminals from registering or completing coordination updates. The lock protects the pidfile recheck, adoption, and spawning; it does not cover the preceding agent queries.

The same lock protects brief coordination work later. For example, when A announces a new loading attempt, it must create the lifetime and cancellation FIFOs, record the attempt, and notify registered terminals. If B arrives during that work, it cannot finish its registration or check that attempt until A releases the state lock. B therefore cannot inspect those resources while A is still updating them. If A dies partway through, B can acquire the released lock and handle the abandoned attempt rather than treating the incomplete records as proof that loading is still active.

The state lock is acquired and released separately for each protected section. It is **not held while querying an existing agent, waiting for Enter or a FIFO event, or waiting for the key-loading `ssh-add` command to obtain a passphrase and finish**, and it is not inherited by that child. Starting a new `ssh-agent` still happens under the state lock, so cooperating terminals cannot both start one. Holding the state lock does not give a terminal permission to load or clear keys; that requires the activation lock.

### Activation Lock: Allow Only One Loading Operation at a Time

**Purpose:** Prevent cooperating Keychain invocations from loading or clearing SSH keys at the same time, including while a loading operation waits for a passphrase.

**Resource:** `paths.activation_lockf`, stored as `<host>.activation.lock`.

Suppose A and B both need the same encrypted SSH key. A wins the activation lock and starts `ssh-add`, which asks for the passphrase. B must not start a second competing key-loading operation while A's is still running. The activation lock remains held throughout A's operation, including the time spent waiting for the passphrase. Simply displaying Keychain's Enter prompt does not hold this lock: a terminal claims loading ownership only when it attempts activation. Both startup `--clear` and standalone `wipe --ssh` take this lock, using the same ownership path, so they cannot clear keys during a cooperating Keychain's loading operation.

A does not retain the state lock while `ssh-add` runs. B can therefore acquire the state lock briefly to register and check for A's operation, then release it and wait. The activation lock tells B that an operation still owns the right to load keys. The lifetime FIFO gives B a way to wake when that operation ends, even if A crashes without sending a completion message. Checking for A's ownership does not transfer ownership to B.

Now suppose A's Keychain process dies while its `ssh-add` child is still asking for the passphrase. The child inherited both the activation-lock descriptor and the lifetime-FIFO writer, so B continues waiting rather than starting an overlapping operation. If neither A nor its child survives, the OS releases the lock and closure of the lifetime FIFO wakes terminals watching it. A stale `loading` entry in the state file cannot keep that lock held.

Using two locks allows shared setup and coordination to continue while one terminal is busy loading keys. Holding only the state lock for the entire passphrase interaction would block other terminals from registering or requesting takeover. Releasing all locks during that interaction would instead allow overlapping loading operations. The activation lock remains held while the state lock is available for those brief updates.

### State File: Record What Happened, Not Who Is Alive

**Purpose:** Record the latest loading attempt and its status, so a waiting terminal can recover the recorded outcome if it misses a completion message. The file does not determine whether a process is alive.

**Resource:** `paths.state_file`, stored as `<host>.state.json`.

Suppose A finishes loading keys, records success, and then dies before sending B a completion message. B wakes because A's lifetime FIFO closes. The state file lets B look up the recorded outcome for the attempt it was watching. B checks that the attempt identifier matches; this file contains only the latest record, not a history of every attempt.

The record contains only the attempt identifier and status:

```json
{"attempt": "0123456789abcdef0123456789abcdef", "status": "success"}
```

The statuses written to disk are `loading`, `success`, `failed`, and `canceled`. The `loading` value describes what was last recorded; it does not authorize waiting. The record contains no passphrases, private keys, key lists, waiter list, process IDs, heartbeat, or authoritative liveness flag.

Now suppose A dies before recording a final outcome. The file may still say `loading`, but that cannot keep the activation lock held or prevent the lifetime FIFO from closing. If A's loading child survives, B continues waiting for that child. Only after observing lifetime closure does B treat a matching `loading` record as an abandoned attempt, not a still-running operation. Even a saved `success` does not prove B's requested keys are currently available: B checks the actual agent before deciding it is done.

### Notification FIFO: Deliver Start and Completion Messages

**Purpose:** Tell each registered waiting terminal when a loading attempt starts and how it finishes, without requiring that terminal to repeatedly check the state file.

**Resource:** `waiter.endpoint`, stored as `wait.<pid>.<random>.fifo` in the waiters directory.

Suppose B is already waiting when A starts loading. B created and opened its own notification FIFO when it registered. A finds that FIFO and sends a start message identifying its attempt. On normal completion, A sends a result message to the same FIFO. Each waiting terminal has its own FIFO, so a message sent to B is not consumed by another terminal instead. A delivered message remains queued until B reads it, even if B was not yet asleep waiting for it.

Creating this FIFO is B's registration; there is no separate JSON list to keep synchronized. B removes its own FIFO when it finishes. The FIFO's presence alone does not prove B is alive, and a start message alone does not prove A is still loading. Before waiting for A, B checks the activation lock and opens A's lifetime FIFO as described below.

### Lifetime FIFO: Wake Waiters When Loading Ends

**Purpose:** Wake waiting terminals when the loading operation ends, without depending on the loader sending a completion message. This is needed because a process can die before sending that message. Detecting the end of the operation does not establish whether loading succeeded.

**Resource:** `owner.life`, stored as `life.<attempt>.fifo` in the waiters directory.

Suppose A is loading keys and B needs to wait for it. Before waiting, B checks that the activation lock is held and opens the read end of the named pipe belonging to A's attempt. A and its `ssh-add` child keep the write end open. B watches for the last writer to close, rather than expecting to receive a message through this pipe.

Now suppose A and its child are killed. Neither can send a completion message, but the operating system closes their open pipe handles. With no writer remaining, all terminals watching this pipe can wake. Normal cleanup produces the same closure. If only A dies and its child survives, the child's open writer keeps B waiting, just as its inherited activation lock prevents overlapping loading.

**No messages are written to this FIFO, and observers never read from it.** They watch for the operating system's closure indication. This is different from the notification FIFO, which carries messages that must be read. After waking, B checks the outcome information and the actual agent before deciding whether to finish or retry.

### Cancellation FIFO: Request Takeover Without Stealing Ownership

**Purpose:** Let a waiting terminal ask the current loader to stop safely, so the requesting terminal can try to take over key loading without running a competing operation alongside it.

**Resource:** `owner.cancel`, stored as `cancel.<attempt>.fifo` in the waiters directory.

Suppose A is prompting for a passphrase, but the user wants to enter it in B instead. When the user types `takeover` in B, B sends a cancellation request to A's cancellation FIFO. A's listener receives it, terminates its loading child, waits for that child to exit, records cancellation, and releases ownership. B can then compete for the activation lock before starting its own loading operation.

Sending this message does not grant B the lock or let B start a second `ssh-add` immediately. The request asks A to stop safely; the activation lock still determines when another terminal may load keys. If A cannot respond, B reports the unsuccessful takeover and continues waiting rather than stealing the lock.

### Waiters Directory: Keep the FIFO Paths Together

**Purpose:** Give cooperating Keychain invocations a common place to find the notification, lifetime, and cancellation pipes they need to communicate.

**Resource:** `paths.waiters_dir`, stored as the private `<host>-waiters/` directory.

This directory contains each terminal's notification FIFO and each loading attempt's lifetime and cancellation FIFOs. A can find registered terminals here to notify them; B can find the channels belonging to the active loading attempt. The directory is not another lock, and leftover files do not by themselves establish that any process is alive.

Each loading attempt has a fresh random identifier. Suppose A's operation ends and another operation starts while B is still watching A's lifetime FIFO. The new operation uses a different FIFO path, rather than reopening A's old channel and concealing its closure. The same attempt identifier connects the new operation's lifetime FIFO, cancellation FIFO, notifications, and state-file record.

## Startup and Coordination Lifecycle

This is the full lifecycle of an `add` invocation, including the traditional invocation with key names and no explicit action. It describes normal operation with locking enabled. `agent start` uses the same agent-setup path with no requested keys. The implementation is in `KeychainApp._handle_add_action`, `_do_add`, `_coordinate_ssh_keys`, and `_try_activation`, together with the coordination classes.

Each subsection that uses the state lock starts with its acquisition and ends with its release. Other subsections explicitly describe work done without that lock. With a stable pidfile, the usual prompt-mode path with missing keys acquires and releases the state lock three times before its first wait: confirming agent selection or starting an agent, terminal registration, and the first waiting-loop check. A pidfile change during setup causes a retry, with another acquisition and release. An explicit `--clear` adds its own ownership and completion operations before the key check.

### Resolve Configuration and Requested Keys

**Neither coordination lock has been acquired yet.**

Keychain parses its options, applies configuration, validates the requested operation, ensures its working directory exists, and resolves the requested key names. `--no-passphrase` (also called `--noask`) bypasses key resolution. In the normal non-quick path, if every requested key is missing, `--ignore-missing` returns successfully without starting an agent; otherwise Keychain reports an error.

### Inspect Existing Agent Candidates

**Neither coordination lock is held.**

Read the pidfile's socket/PID information and retain it for comparison. Follow the existing selection policy to validate a pidfile agent or an allowed inherited agent. If `--quick` is requested, first check whether the pidfile agent is valid and already contains keys. These checks can query the agent, so they run outside the state lock. A slow answer does not by itself mean the agent is dead or authorize replacing it.

### Confirm Agent Selection or Start an Agent

**Acquire the state lock.** This is the first state-lock acquisition.

Reread the pidfile's socket/PID information and compare it with the saved observation. If it changed, make no setup changes during this acquisition. After releasing the lock, return to [candidate inspection](#inspect-existing-agent-candidates) and repeat the checks using the current pidfile.

If the pidfile is unchanged, accept a successful quick check or the selected existing agent, writing its pidfiles where appropriate. If no acceptable agent was found, start one and write its pidfiles while still holding the state lock. Spawning remains serialized; the agent queries do not. No activation lock is needed for this work.

**Release the state lock.**

### Export the Selected Agent Environment

**Neither coordination lock is held.**

Once agent setup succeeds, emit requested `--eval` output and update the systemd user environment if requested. A systemd update does not hold up other terminals' access to the state lock.

### Apply Startup Options

**Neither coordination lock is held on entry to this section.**

If `--clear` was requested, perform the [ownership acquisition](#claim-key-loading-and-announce-the-attempt), [operation](#load-keys-and-finish-child-cleanup), and [completion](#publish-the-outcome-and-release-ownership) described below, with an SSH identity wipe instead of key loading. Each of those sections shows which locks it uses. If another loader owns the activation lock, retry ownership acquisition subject to `--lockwait`. After clearing finishes and both locks are released, resume here. Clearing precedes the normal missing-key check, so it is an exception to activation being needed only when keys are missing. `--quick` and `--clear` cannot be combined.

With `--no-passphrase`, return after agent setup and any requested clear; neither load SSH keys nor warm GPG keys. If `--quick` found an existing populated pidfile agent during setup, skip further key loading and return. An unsuccessful quick check continues with SSH loading, but `--quick` never warms GPG keys.

### Check the Requested SSH Keys

**Neither coordination lock is held.**

Query the selected agent for missing SSH keys and PKCS#11 identities. This is an initial observation, not a reservation to load keys. A terminal that later acquires activation ownership rechecks what is missing before loading.

### Choose the Loading Route

**Neither coordination lock is held.**

If nothing is missing, proceed to [cleanup and exit](#clean-up-and-exit) without activation ownership or FIFO registration. This includes `agent start`, which has no requested keys.

If keys are missing but Keychain cannot open a controlling terminal, or the platform lacks FIFO support, skip registration and the waiting loop and proceed directly to [ownership acquisition](#claim-key-loading-and-announce-the-attempt). If another loader owns the activation lock, retry subject to `--lockwait` (default: 5 seconds), then report an error if it remains unavailable. This direct route has no Keychain Enter prompt or takeover interaction; `ssh-add` still needs a way to obtain any required passphrase. A FIFO creation or access error is reported, not silently bypassed.

Otherwise, continue with terminal registration below.

### Register the Waiting Terminal

**Acquire the state lock.** This is a separate acquisition for registration.

Create and open this terminal's notification FIFO. The FIFO itself is the registration; no JSON waiter list is maintained. No activation lock is held.

**Release the state lock.**

### Recheck Keys After Registration

**Neither coordination lock is held.**

Query the agent again because another terminal may have finished loading before registration completed. If all requested keys are available, proceed to [cleanup and exit](#clean-up-and-exit). Otherwise, announce which keys need loading and enter the waiting loop below.

### Process Notifications and Check for a Loader

**Acquire the state lock.** This begins one pass through the waiting loop. Every subsequent pass acquires it again; the lock is not retained between passes.

First check queued completion messages and any lifetime FIFO already being watched. A completion message or closure of that FIFO supplies an outcome to process after releasing the state lock. If an observed operation is still active, continue watching it without repeating the activation-lock checks below.

**When the loader check is needed:** this terminal has no completion to process and is not already watching a lifetime FIFO. This check runs here, within the waiting loop, not as a background task.

Suppose terminal B still needs keys. Before it displays the Enter prompt or tries to load them immediately, it must check whether terminal A is already loading keys. If A is loading, B also needs a way to wake up when that operation ends, even if A crashes without sending a completion message. The activation lock answers whether an operation is active; the lifetime FIFO provides that wakeup.

**Try to acquire the activation lock, without waiting.** If B acquires it, no other loader owns it. While holding both locks, remove abandoned lifetime and cancellation FIFO files. These are leftover coordination files, not keys or agent files.

**Release the activation lock if that check acquired it.** The result is "no active loader"; skip the remaining loader checks. B has only checked for an existing operation, not claimed ownership to load its own keys.

**If another process held the activation lock, open its lifetime FIFO instead.** A surviving `ssh-add` child can hold the lock even if its parent Keychain has died. Keep the FIFO's read end open so B can detect when all writers close it, but do not read from it. If no valid lifetime FIFO can be opened, report an error rather than wait without a way to detect completion.

**Try to acquire the activation lock a second time, without waiting.** This second check is only needed after opening the FIFO: the operation may have died between the first check and the open. If B now acquires the lock, close B's newly opened FIFO handle and remove the abandoned lifetime and cancellation FIFO files.

**Release the activation lock if the second check acquired it.** The result is "no active loader". If the second check instead found the lock still held by another process, retain the FIFO handle and report "active loader". B holds no activation lock in either case. If the active operation ends immediately afterward, FIFO closure will wake B without requiring a completion message.

The state lock has remained held throughout this section, preventing any new owner from publishing an attempt between the checks. It cannot prevent an existing process from dying. If no loader was found but B received a start message for an attempt it has not yet processed, prepare that ended attempt's outcome for evaluation. Otherwise, prepare either to wait for the active operation or to follow the no-loader behavior below. Do not wait for keyboard input or a FIFO event while holding the state lock.

**Release the state lock.** Every exit from this pass releases it, including completion and error paths.

### Wait or Attempt Loading

**Neither coordination lock is held.**

A completion proceeds to [outcome evaluation](#evaluate-the-outcome). With an active loader, both modes wait, and prompt mode also offers takeover. With no active loader, prompt mode waits for Enter; immediate mode proceeds to [ownership acquisition](#claim-key-loading-and-announce-the-attempt). Enter with no active loader also proceeds to ownership acquisition. Checking that there was no loader did not reserve the lock: another terminal may win it first.

A FIFO event returns to [the waiting-loop check](#process-notifications-and-check-for-a-loader), which acquires and releases the state lock for another pass. Typing `takeover` follows the separate [takeover path](#takeover-while-waiting). No state lock or activation lock is held while sleeping or waiting for input.

### Claim Key Loading and Announce the Attempt

**Acquire the state lock.** This acquisition protects the attempt to become the loading owner and announce that attempt.

**Try to acquire the activation lock, without blocking.** If another loader owns it, skip publication. Otherwise, retain the activation lock through the operation and completion.

With both locks held, remove abandoned lifetime/cancellation channels, create the new channels, save a fresh `loading` record, and notify registered terminals. No `ssh-add` child has been prepared or started yet.

**Release the state lock.** If this terminal acquired the activation lock, it retains that lock; otherwise, it holds neither lock.

### Load Keys and Finish Child Cleanup

**The state lock is not held.** Only the terminal that acquired the activation lock may perform this work. A registered terminal that lost the lock returns to the waiting loop instead; a direct invocation retries ownership acquisition subject to `--lockwait`.

For a key-loading operation, the owner rechecks the missing keys while holding the activation lock: another terminal may have loaded them before this invocation won it. If nothing remains to load, set the outcome to success and proceed to completion without running `ssh-add`. Otherwise, prepare the commands. An explicit clear operation uses the separate [SSH clearing path](#clearing-ssh-identities) instead; it has no requested keys to check or load.

Start the cancellation listener and run the prepared `ssh-add` commands sequentially. Each child inherits the activation-lock descriptor and lifetime-FIFO writer. The state lock is not held while waiting for a passphrase or child exit. A takeover request asks the owner to terminate and reap its child; it does not steal the lock or launch an overlapping child.

On completion, cancellation, or an exception that allows cleanup, stop the listener and terminate/reap any unfinished child. Finish this cleanup before acquiring the state lock again. The activation lock remains held throughout this section.

### Publish the Outcome and Release Ownership

**Acquire the state lock.** This is a new acquisition for completion publication and resource cleanup. The owner still holds the activation lock.

Save `success`, `failed`, or `canceled`, then send completion notifications. A failed final save still leads to resource cleanup.

**Release the owner's activation-lock descriptor.** If an inheriting child or helper still holds a descriptor, the kernel lock remains held until that last descriptor closes.

Close the owner's lifetime and cancellation endpoints. Lifetime closure wakes observers when no inherited writer remains. Retain the lifetime pathname if a surviving writer still needs to be discoverable.

**Release the state lock.**

### Evaluate the Outcome

**This Keychain invocation holds neither coordination lock.**

A successful loading owner proceeds to cleanup. A canceled owner waits for the takeover result, and a failed owner reports its error. A completed startup `--clear` instead returns to [startup options](#apply-startup-options), before the ordinary missing-key check. Standalone `wipe --ssh` finishes without entering the key-loading flow.

Waiting terminals reach this section after a waiting-loop pass reports completion and releases the state lock. Each queries the actual agent: available requested keys mean success, regardless of a stale saved result. If keys remain missing after `success`, an immediate terminal competes for activation ownership to load them; a regular terminal returns to the Enter prompt. If the outcome is `failed` or unknown and keys remain missing, immediate mode reports an error instead of automatically starting another attempt, while prompt mode offers a retry. An abandoned attempt allows immediate mode to compete again and prompt mode to return to Enter. A canceled attempt follows the [takeover/handoff behavior](#prompt-immediate-and-takeover) described later in this document.

For example, A may successfully load key A while B requested key B. A's success is not a failure for B, but it does not satisfy B either. In immediate mode, B tries to acquire the activation lock, rechecks key B after acquiring it, and loads it if still needed. The two loading operations do not overlap. A saved status never substitutes for checking the agent.

### Clean Up and Exit

**Neither coordination lock is held.**

When SSH coordination finishes or raises an error, close this terminal's lifetime observation handle and remove its own notification FIFO in a `finally` block. This does not rewrite JSON. Invocations that did not register have nothing to remove.

After successful SSH handling, perform any requested GPG signing/decryption warm-up outside SSH activation coordination, unless `--quick` or `--no-passphrase` excluded it. Return success, or report an error if the operation failed. The SSH agent normally remains running for later shells; coordination locks protect setup and key loading, not the agent's entire lifetime.

## Clearing SSH Identities

`wipe --ssh` and startup `--clear` use `_activate_direct` and `_try_activation`, the same ownership path used for direct key loading. They pass no requested keys and request a wipe instead. Plain `wipe` defaults to the SSH operation; an explicit GPG wipe remains outside SSH activation coordination.

Suppose A is waiting for an SSH key's passphrase when B runs `keychain wipe --ssh`. B must acquire the activation lock before running `ssh-add -D`. It retries ownership acquisition subject to `--lockwait` (default: 5 seconds) and reports a lock error if it cannot acquire ownership. `keychain wipe --ssh --lockwait 0` makes one acquisition attempt without waiting for a busy lock. This deadline controls lock acquisition, not how long the agent may take to answer the wipe command.

After acquiring ownership, B releases the state lock and calls `SshAgent.wipe` while retaining the activation lock. There is no missing-key query or loading step. The shared completion path reacquires the state lock, records the attempt's outcome, notifies waiters, and releases ownership. Waiters still check their own requested keys; completion of a wipe does not mean their keys are available.

Standalone `wipe --ssh` selects an existing agent but does not start one. Startup `--clear` differs only in the surrounding workflow: `add` has already prepared an agent, and ordinary loading may follow the clear. Clearing neither offers an Enter prompt nor runs the loading child's takeover listener.

**Remaining crash-handling limit:** Keychain itself holds the activation lock during a wipe, but the `ssh-add -D` child does not inherit that lock or the lifetime writer. If only Keychain is killed with `SIGKILL`, a surviving wipe child could continue after its parent's lock is released. The inherited-descriptor protection described for key loading does not yet cover clearing; the normal wipe-exclusion tests do not test this abrupt-termination case.

## Takeover While Waiting

This conditional path begins only when a waiting terminal types `takeover`. Sending the request does not grant activation ownership to that terminal.

### Send the Takeover Request

**Acquire the state lock.**

Send a cancellation message to the observed attempt's cancellation FIFO. If there is no observed attempt, prepare to attempt loading instead. If the message cannot be delivered, report that takeover is unavailable. The requester holds no activation lock.

**Release the state lock.**

### Wait for the Takeover Response

**Neither coordination lock is held while waiting.**

After delivering the request, wait for the owner's response using the normal waiting loop. The response deadline is `_CHILD_TERMINATE_TIMEOUT + 2.0`: currently seven seconds. The child first receives a termination request and has up to five seconds to exit before it is killed and reaped. The response allowance is longer so using the full termination grace period does not itself exhaust the requester's wait. Each pass through [the waiting-loop check](#process-notifications-and-check-for-a-loader) acquires and releases the state lock; it is never held while sleeping.

The requesting terminal remembers which attempt it asked to cancel. If the response deadline expires, it reports that cancellation has not been confirmed and resumes ordinary waiting, but keeps that attempt identifier. A later matching `canceled` result still lets it compete for activation ownership without another Enter. Other terminals follow the [handoff behavior](#prompt-immediate-and-takeover) described below. An undeliverable request clears the remembered request; a matching completion consumes it. A deadline expiring never grants ownership or releases another process's lock.

## Failure and Registration Ordering

An uncatchable termination such as `SIGKILL` skips Python cleanup. The kernel still closes that process's descriptors. If `ssh-add` survives, its inherited descriptors retain ownership; otherwise lifetime closure wakes observers, which check the agent and the recorded outcome before deciding whether to retry. Stale JSON does not retain an OS lock. Explicit `--no-lock` disables the locking and FIFO-coordination guarantees above rather than providing another coordinated mode.

The tests cover both startup orders below. These are cases to understand during design review, not outstanding test tasks:

- **B registers before A starts loading:** A finds B's notification FIFO and sends the start message before starting its child. B does not have to be asleep waiting for messages yet; messages remain queued until it reads them. `test_completed_notification_survives_result_overwrite` registers B first, lets A finish before B starts waiting, and verifies that B receives A's queued completion even after another result replaces the JSON record.
- **A starts loading before B registers:** B can finish registration only after A releases the state lock used to publish its attempt. If A is still loading when B reaches [the loader check](#process-notifications-and-check-for-a-loader), B opens A's lifetime FIFO and waits for completion. It does not need the start message sent before B registered. `test_waiter_observes_successful_loading` exercises this order with real `ssh-add` processes and terminals, in both prompt and immediate modes.

The additional test `test_owner_death_during_discovery_cannot_leave_waiter_asleep` ends the operation between the first activation-lock check and opening the FIFO. It verifies that the second lock check detects this and returns without leaving B waiting for an operation that has already ended.

A process killed during publication cannot have started `ssh-add` yet. Waiters that received the start message can detect the abandoned operation. A regular terminal that never received that message remains at its original Enter prompt, with no loading operation having taken place.

## Why Death Wakes Waiters

The loading Keychain holds the write end of its lifetime FIFO open, and passes that descriptor to `ssh-add`. Observers open only its read end. No data is written to this FIFO.

```text
Keychain loader ---- lifetime writer ----+
                                        +---- read ends in waiting terminals
ssh-add child ------ lifetime writer ----+
```

When all writer descriptors close, end-of-file makes the readers ready in `select()`, without a completion message or periodic JSON checks. Observers notice readiness but **never read the lifetime FIFO**. Reading EOF can clear the shared readiness indication on macOS and prevent another observer from waking. Killing only Keychain leaves the child writer open; killing the whole loading process group closes both. This is deliberate.

The notification FIFO is different: its waiting terminal holds a writer open to avoid idle end-of-file. Its job is to carry messages, not prove the loader is alive. Buffered messages are consumed before calling `select()` again, so a second message already read into Python memory cannot be overlooked.

## Why Another Loader Cannot Overlap

Keychain also passes the activation lock descriptor to `ssh-add`. POSIX lock release closes Keychain's descriptor rather than issuing `LOCK_UN`, because an explicit unlock would also unlock the descriptor inherited by the child. The lock remains held until the last inherited descriptor closes.

On orderly exit or a handled termination signal, Keychain terminates and reaps any unfinished child before completing the attempt. On `SIGKILL`, Python cleanup cannot run, but the child's inherited descriptors still protect the operation until the child exits.

The short state lock is never inherited by a child. No state lock is held while waiting for keyboard input, FIFO events, a passphrase, or child termination. The only attempt to acquire the activation lock while holding the state lock is nonblocking. A loading owner can therefore reacquire the state lock to finish without forming a circular lock wait.

## Completion and Missing Notifications

Normal completion saves the attempt result, sends completion messages, and closes the loading terminal's resources under the short state lock. A waiter first checks queued messages; lifetime closure provides an independent way to notice completion.

If Keychain dies after saving the result but before notifying everybody, observers wake on lifetime closure and read the matching result. If it dies earlier, the last matching record still says `loading`, and observers classify the operation as abandoned. They always check the real agent before deciding what to do next: an orphaned `ssh-add` may have successfully loaded the keys.

If the JSON file is removed or malformed, notification delivery still works because registration is represented by actual FIFOs. A matching completion message can supply the outcome. If neither a message nor a matching saved result is available, the outcome is unknown, not invented success. An unreadable file reports an error instead of silently pretending to be an empty record.

The file stores only the latest result, not a history. A slow waiter normally has its completion message queued. If that message is unavailable and a newer attempt has already overwritten the result, the waiter cannot reconstruct the earlier outcome: it checks the agent and reports failure in immediate mode if the requested keys remain missing. This is intentionally conservative.

## Prompt, Immediate, and Takeover

| Situation | Regular terminal | Immediate terminal |
| --- | --- | --- |
| No operation is active and keys are missing | Wait for Enter | Try to acquire the activation lock |
| Another loading operation is alive | Wait; offer takeover | Wait without a Keychain input prompt |
| Requested keys become available | Succeed | Succeed |
| Another attempt succeeds but this terminal still needs keys | Return to the Enter prompt | Compete to load the remaining keys |
| Another attempt fails and keys remain missing | Offer a retry | Fail; do not start a chain of repeated prompts |
| Another attempt's outcome is unknown and keys remain missing | Offer a retry | Fail; do not assume success |
| An observed attempt is abandoned before recording a result | Return to the Enter prompt | Compete to recover the abandoned attempt |
| Another terminal requests takeover | Cancel the child, then wait for the successor | Same behavior |

Takeover uses the cancellation FIFO belonging to the observed attempt. The owner stops and reaps its child, records `canceled`, and releases ownership. The requesting terminal competes for the activation lock; it does not steal a live lock. Other terminals remain waiting. The existing one-second handoff grace period applies only while there is no successor; once one is observed, waiting is driven by its lifetime channel. The [takeover response deadline](#wait-for-the-takeover-response) is longer than the child termination grace period, and a late response does not erase the requester's intent.

The cancellation-listener thread retains its bounded 0.5-second stop check. It does not poll JSON or infer process death. Ordinary terminal waiting and loader-death detection do not periodically poll the state file.

## Cleanup and Security

- A waiting terminal removes only its own FIFO and closes its observation descriptor. Cleanup does not depend on reading or rewriting JSON.
- FIFO writes reject symlinks, regular files, and FIFOs not owned by the current user. A pathname in a JSON record can no longer redirect notifications, because JSON contains no notification paths.
- Dead notification FIFOs with no reader can be removed during notification. Abandoned lifetime FIFOs and their cancellation endpoints are removed only while both locks are held, during discovery or before publishing the next attempt.
- If an inherited lifetime writer remains open in a child or helper, the lifetime pathname is retained so a newly arriving terminal can still discover it.
- Atomic JSON replacement is retained. A failed replacement leaves the prior complete record intact. Failure to save a final result does not prevent closing the lifetime channel and releasing Keychain's lock descriptor.

## Limits Worth Auditing

### macOS Validation Finding

Apple's `fifo_read` implementation clears the shared EOF indication after an empty read. The first implementation read the lifetime FIFO during discovery and cleanup, which could clear the indication before another observer's `select()` noticed closure. Neither path reads it now: discovery checks the lock, and cleanup uses non-consuming readiness to preserve a pathname while a child still holds its writer. See [Apple's FIFO implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/miscfs/fifofs/fifo_vnops.c), particularly `fifo_read`, `fifo_select`, and `fifo_close_internal`.

The test harness drains output from every pseudo-terminal while waiting, as real terminal windows do, including during interrupted process exit. Recovery tests check lock release after the successor finishes: an immediate successor may already own the lock when the previous owner exits, so checking for an unlocked file at that moment would incorrectly reject successful recovery.

### Other Limits

An agent query has no new response timeout. A suspended agent, or an agent waiting for a graphical confirmation, can still leave a querying Keychain invocation waiting for its answer. The fix prevents that query from retaining the state lock; it does not make an unresponsive agent answer or classify a slow agent as dead. Other terminals can still acquire the state lock, although their own queries to that same agent may also wait. A query made after acquiring activation ownership retains the activation lock, so another loader cannot overlap it.

This is not a guarantee against arbitrary interference with a live `.keychain` directory. Unlinking an active lock file can create a second lock inode; deleting a live waiter's FIFO can prevent future senders from reaching it. Processes running as the same user can also intentionally hold or tamper with that user's coordination resources. The design protects normal concurrency, process termination, stale records, damaged JSON, and validated IPC paths; it is not a security boundary against the account owner.

Inherited lock and FIFO descriptors depend on the invoked OpenSSH program retaining them. The real-process regression test verifies this with the installed `ssh-add`. A wrapper that deliberately closes inherited descriptors is not equivalent to the tested executable. An askpass helper that inherits and retains the descriptors can also keep the operation protected; a remaining writer is not treated as permission to start overlapping key loading.

If Keychain is killed but `ssh-add` survives, the original passphrase prompt may remain usable. Other terminals wait for that child. The dead parent's cancellation listener cannot handle takeover requests; Keychain reports that takeover was unavailable rather than sending signals to an unverified PID.

Old and new coordination implementations should not participate in the same active loading session. A held activation lock without a discoverable lifetime channel produces a clear error for an automatic contender rather than waiting forever. Old JSON fields alone do not prevent a new invocation from proceeding.

## Review Map

Read `src/keychain/coordination.py` in this order:

1. `ActivationOwner.__enter__`: nonblocking ownership acquisition, publication, and startup ordering.
2. `ActivationOwner._run_child`: the two inherited descriptors and subprocess handling.
3. `ActivationOwner.__exit__`: child cleanup, result publication, and resource release.
4. `ActivationWaiter.wait`: one wait loop for terminal input, notifications, and lifetime closure.
5. `ActivationWaiter._completion`: matching a saved outcome to the observed attempt.

Then read `SshAgent.start` in `src/keychain/agents.py` for the unlocked candidate checks and locked pidfile recheck and spawning. In `src/keychain/main.py`, `KeychainApp._coordinate_ssh_keys` applies prompt/immediate policy, remembers pending takeover requests, and verifies actual agent contents. `_handle_wipe_action` and `_do_add` both reuse `_activate_direct` for SSH clearing. These callers do not edit JSON or register/unregister waiters in a saved list.

## Test Coverage

`tests/test_coordination.py` covers malformed and unreadable records, atomic replacement failures, partial and buffered FIFO messages, unsafe notification paths, stale FIFOs, missing completion notifications, lock exclusion, publication failure, cancellation during a second child, and resource cleanup. It also verifies that five observers all see closure without reading the lifetime FIFO, that an abandoned channel cannot authorize waiting, and that death between discovery's lock checks cannot leave a waiter asleep. Additional regressions verify unlocked agent queries during startup, quick startup, and the initial key check; takeover of a child that ignores termination; and SSH wipe exclusion while loading is active.

`tests/test_immediate.py` exercises the real coordination machinery with controlled key loading. It covers the four regular/immediate owner-waiter combinations, failure without automatic retry cascades, interactive retry, and takeover. It also checks that an immediate waiter loads a different requested key after the first owner succeeds, and that a late cancellation response lets the requesting terminal take over without a second Enter.

`tests/test_coordination_e2e.py` uses disposable encrypted keys, real `ssh-agent` and `ssh-add` processes, and real pseudo-terminals. It covers abrupt death, orderly signals, surviving children, quiet prompts, five simultaneous terminals, successive takeovers, old JSON records, damaged JSON during loading, and a forced crash after saving success but before sending notifications. Added cases suspend a real agent to verify that a blocked query leaves the state lock available without replacing the agent, load different keys from two immediate terminals, and verify that `wipe --ssh --lockwait 0` refuses to clear during loading but works after loading finishes. Each test owns and cleans up its own agent; it does not operate on the user's keys or agent.

`tests/test_agents.py` checks pidfile changes during candidate validation and before lock acquisition, including quick and inherited-agent paths. A simultaneous-startup test forces two contenders to see no existing agent and verifies that only one spawns. `tests/test_cli_actions.py` verifies that SSH wipe accepts the shared `--lockwait` option and uses its existing help entry.
