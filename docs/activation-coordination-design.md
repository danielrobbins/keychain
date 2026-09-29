# Activation Coordination: Correctness Guide

This describes the current development implementation of SSH key-loading coordination. It extends the lifetime-based design introduced in Keychain 3.0.5: pressing Enter can move a passphrase request to another terminal, and immediate invocations can load keys concurrently and cancel redundant prompts. It does not change agent selection, add a daemon, or make Keychain handle passphrases itself.

## The Problems Being Addressed

An older implementation could save "loading", then die without clearing that record or notifying waiting terminals. The operating system released its lock, but terminals remained asleep waiting for a message that would never arrive. Atomic JSON replacement protected the integrity of a write; it did not make a saved description of a process remain true after that process died. Live locks and open notification channels now determine whether there is an operation to wait for.

A different problem occurs when a hidden interactive shell starts `ssh-add`. Its prompt can be perfectly functional but inaccessible to the user. Prompt mode now lets the user press Enter in a visible waiting terminal to move the request there. Immediate mode lets the visible terminal start its own prompt; after one attempt supplies the needed keys, other live Keychain processes cancel their own redundant children.

Concurrency does not mean that clearing keys may overlap loading. `wipe --ssh` and startup `--clear` still exclude cooperating loading operations.

## The Participants

- A **waiting terminal** is a Keychain invocation that still needs SSH keys but is not currently running its loading child.
- A **loading terminal** owns a loading attempt and runs its own `ssh-add`. More than one loading terminal can be active.
- An **attempt** is one operation with a fresh random identifier, its own lock, and its own notification channels. A clearing operation uses the same resource lifecycle.
- `ssh-agent` is the authority on loaded keys. Another terminal's success message is a reason to check the agent, not proof that this terminal's keys are present.

## Locks and Their Purpose

There are three kinds of lock. The **state lock** protects shared setup and brief coordination updates. The **activation lock** allows loaders to coexist but keeps clearing separate. A **per-attempt lock** identifies the lifetime of one particular operation. All three use operating-system locks; "OS lock" describes the mechanism, not an additional resource.

A **FIFO**, or named pipe, is a communication channel opened through a filesystem path. Notification and cancellation FIFOs carry messages. A lifetime FIFO instead lets observers detect that an operation ended, even without a final message. These channels support the locks; none replaces them.

The resource labels below use `paths` for `KeychainPaths`, `waiter` for `ActivationWaiter`, and `owner` for `ActivationOwner`.

### OS Lock: How Access Is Enforced

**Purpose:** Let the operating system enforce access without relying on a saved PID or a JSON flag.

**Mechanism:** `fcntl.flock`, wrapped by `LockFile`, on each lock file.

Suppose A holds an exclusive lock. B cannot acquire either shared or exclusive access to that file until A releases it. If A holds a shared lock instead, B may acquire shared access, but neither may acquire exclusive access while shared holders remain. The file can remain on disk throughout; its existence is not what makes the lock held.

An open file handle is called a **file descriptor**. Keychain releases a POSIX lock by closing its descriptor, not by issuing an explicit unlock. If a child inherited the descriptor, the lock remains held until the last holding descriptor closes. Process death also closes descriptors. Killing a parent therefore does not release an inherited lock while its child still holds it.

These advisory locks coordinate Keychain invocations using this protocol. They do not prevent a user from running `ssh-add` independently.

### State Lock: Keep Shared Setup and Updates Consistent

**Purpose:** Keep agent setup and coordination updates from interfering with each other.

**Resource:** `paths.state_lockf`, stored as `<host>.state.lock`.

Suppose A and B start together and neither has an agent. Both read the pidfile and validate candidates outside the state lock. A then acquires the lock and rereads the pidfile. If it is unchanged, A can start an agent and write its pidfile before releasing the lock. B subsequently sees the changed pidfile, releases the lock, and repeats its candidate checks. B does not start a duplicate based on its earlier observation.

The same lock protects registration and publication. If A is creating its attempt's files, B cannot inspect those files until A releases the state lock. If A dies partway through, B can acquire the released lock and identify abandoned resources.

Existing-agent queries, passphrase entry, FIFO waits, and child termination do not hold this lock. Starting a new `ssh-agent` still happens under it to prevent duplicate startup. No loading child inherits the state-lock descriptor.

### Activation Lock: Separate Loading From Clearing

**Purpose:** Allow several terminals to load keys while preventing a cooperating clear operation from removing identities during loading.

**Resource:** `owner.gate`, on `paths.activation_lockf`, stored as `<host>.activation.lock`.

Suppose A and B are immediate invocations asking for the same key. Each takes a **shared** activation lock and may run its own `ssh-add`. C runs `keychain wipe --ssh` and needs an **exclusive** activation lock. C cannot obtain it until all loaders release their shared locks. Conversely, while C clears the agent, neither A nor B can start a new loading operation.

A loader retains shared access through its final cleanup. Its `ssh-add` child inherits the descriptor, so killing only the parent does not let a wipe overlap that surviving child. Simply displaying the Enter prompt holds no activation lock.

The activation lock no longer identifies a single loading terminal. That requires the per-attempt locks below.

### Per-Attempt Lock: Identify One Live Operation

**Purpose:** Determine whether a particular attempt is still active, independently of other concurrent attempts.

**Resource:** `owner.lock`, stored as `load.<attempt>.lock` inside `paths.waiters_dir`.

Suppose A and B both load keys. A finishes while B is still prompting. The shared activation lock remains held by B, so it cannot tell an observer that A ended. A's separate exclusive attempt lock can: another process can acquire it only after A and any inheriting child release it.

Each attempt uses a fresh random identifier. Its lock is held from publication through cleanup, and loading children inherit it. Under the state lock, an observer can probe this lock without waiting. If the probe acquires it, the operation is no longer protected and its abandoned files can be removed. If it cannot, the observer opens that attempt's lifetime FIFO and probes the lock again to cover death during discovery.

The actual operation, not a stale status string, therefore determines whether its resources are live.

### State File: Record What Happened, Not Who Is Alive

**Purpose:** Preserve the latest recorded outcome when an observer misses a completion message.

**Resource:** `paths.state_file`, stored as `<host>.state.json`.

Suppose A saves success and dies before notifying B. When A's lifetime channel closes, B can consult the saved outcome, but only if the attempt identifier matches. Concurrent or later attempts may already have replaced that record.

```json
{"attempt": "0123456789abcdef0123456789abcdef", "status": "success"}
```

The file contains only an attempt identifier and one of `loading`, `success`, `failed`, or `canceled`. It contains no passphrases, key lists, waiters, PIDs, heartbeat, or authoritative liveness flag. A matching `loading` record after an operation ends means the final result was not recorded. A nonmatching record means the outcome is unknown. Neither prevents checking the agent or continuing with a needed operation.

Malformed or missing JSON is treated as an absent result. An unreadable file is an error. Registration, lock ownership, and resource cleanup do not require a valid saved result.

### Notification FIFO: Deliver Start and Completion Messages

**Purpose:** Tell each registered terminal about other attempts without requiring it to repeatedly read JSON.

**Resource:** `waiter.endpoint`, stored as `wait.<pid>.<random>.fifo` inside `paths.waiters_dir`.

Suppose B registers before A starts. A sends B a start message and later a completion message. Messages remain queued until B reads them. Each terminal has its own FIFO, so another terminal cannot consume B's message.

Creating this FIFO is registration; no separate waiter list is maintained. A loading terminal retains its registration so its listener can react to other loaders' results. Its own attempt's notifications are ignored.

### Lifetime FIFO: Wake Observers When an Operation Ends

**Purpose:** Wake observers even if a loader dies without sending a completion message. Closure establishes that the operation ended, not that it succeeded.

**Resource:** `owner.life`, stored as `life.<attempt>.fifo` inside `paths.waiters_dir`.

Suppose B observes A's held attempt lock. B opens the read end of A's lifetime FIFO. A and its loading child keep the write end open. When the last writer closes, the operating system makes B's reader ready, even if neither process had a chance to send a message.

Observers **never read from this FIFO**. They only watch its readiness. An empty read can clear the shared EOF indication on macOS before another observer notices it. Killing only A leaves its child's writer open; killing both closes the operation's writers.

The ordinary notification FIFO is different: messages must be read, and its owner keeps a writer open to avoid idle end-of-file.

### Cancellation FIFO: Move a Passphrase Request

**Purpose:** Ask live Keychain processes to stop their own loading children, rather than sending signals to PIDs taken from saved metadata.

**Resource:** `owner.cancel`, stored as `cancel.<attempt>.fifo` inside `paths.waiters_dir`.

Suppose A is prompting in a hidden terminal and the user presses Enter in waiting terminal B. B sends cancellation requests to the attempts it currently observes. Each live owner terminates and reaps its own child, records cancellation, and releases its attempt lock. B waits for those attempts to finish before starting a replacement.

B does not steal a lock. An undeliverable request or an unresponsive owner is reported. Takeover does not prevent a newly arriving immediate invocation from starting independently.

### Waiters Directory: Keep Resources Discoverable

**Purpose:** Give cooperating invocations one place to find registered terminals and individual attempts.

**Resource:** `paths.waiters_dir`, stored as the private `<host>-waiters/` directory.

The directory contains notification FIFOs and each attempt's lock, lifetime FIFO, and cancellation FIFO. The attempt identifier joins those resources together. New attempts never reuse an old lifetime channel.

A leftover file does not prove a process is alive. Discovery checks locks before removing abandoned attempt files. A lifetime pathname is retained if an inheriting child or helper still has its writer open, so later arrivals can discover that operation.

## Startup and Coordination Lifecycle

This is the lifecycle of an `add` invocation, including traditional invocations with key names and no explicit action. It assumes locking is enabled. `agent start` uses the same agent-setup path without requested keys.

Each protected subsection begins with a state-lock acquisition and ends with release. A later subsection takes the lock again; none retains it across agent queries, user input, or loading-child execution.

### Resolve Configuration and Requested Keys

**No coordination lock is held.**

Parse options, resolve configuration, ensure the working directory exists, and resolve key names. `--no-passphrase` bypasses key resolution. When all requested keys are missing in the normal non-quick path, `--ignore-missing` succeeds without starting an agent; otherwise report an error.

### Inspect Existing Agent Candidates

**No coordination lock is held.**

Read the pidfile and retain its socket/PID information for comparison. Apply the existing agent-selection policy. A `--quick` check also queries whether a valid pidfile agent already contains keys. These queries can wait for the agent, so they run outside the state lock. A slow answer is not permission to replace it.

### Confirm Agent Selection or Start an Agent

**Acquire the state lock.**

Reread the pidfile. If it changed, make no setup changes, release the lock, and repeat candidate inspection. Otherwise, accept the selected agent or successful quick result and write pidfiles as appropriate. If no acceptable agent exists, start one and publish its pidfiles while still holding this lock.

**Release the state lock.**

### Apply Startup Options

**No coordination lock is held on entry.**

Emit any requested `--eval` output and update the systemd user environment if requested. If `--clear` was requested, perform the separately described clearing operation before checking missing keys. That operation acquires and releases its own locks.

With `--no-passphrase`, return after setup and any clear. A successful quick check skips further loading. An unsuccessful quick check continues with SSH loading, but `--quick` never warms GPG keys. `--quick` and `--clear` cannot be combined.

### Check Requested Keys and Choose a Route

**No coordination lock is held.**

Query the selected agent for missing file keys and PKCS#11 identities. If nothing is missing, no loading attempt or waiter registration is needed.

Without a usable controlling terminal or FIFO support, use the direct loading route: attempt ownership and retry a busy activation lock subject to `--lockwait`. This route has no Enter prompt or peer-result listener. Where FIFOs are supported, it still publishes an attempt and listens for incoming cancellation. `ssh-add` remains responsible for obtaining a passphrase.

Otherwise, register below. A FIFO access error is reported, not silently bypassed.

### Register the Terminal

**Acquire the state lock.**

Create and open this terminal's notification FIFO. No activation or attempt lock is held.

**Release the state lock.**

### Recheck Keys After Registration

**No coordination lock is held.**

Check the agent again because another terminal may have finished just before registration. If keys remain missing, announce them and enter the waiting loop. Registration preceding this check ensures subsequent attempts can notify this terminal.

### Process Notifications and Discover Active Attempts

**Acquire the state lock.** Each pass takes and releases it separately.

First consume queued completion messages and check the lifetime handles already open. Completion produces an outcome to evaluate after releasing this lock.

Otherwise, discover the currently published attempts, excluding this invocation's own attempt when called by a loading listener. For each attempt, try its exclusive lock without waiting. If acquired, remove its abandoned lock and channel files and release that probe lock. If held, open its lifetime reader and repeat the lock probe. If the second probe acquires it, close the reader and remove the abandoned files; otherwise retain the reader for observation.

The second probe covers a process dying between the first probe and opening its FIFO. The state lock prevents a new operation from being published partway through discovery, but cannot prevent an existing process from dying.

Remember attempts announced by start messages as well as those found through discovery. If one disappears before its lifetime reader was opened, evaluate its outcome rather than sleeping for a message that may never arrive. If an activation lock is exclusively held but no corresponding attempt can be observed, report an unavailable lifetime channel rather than waiting blindly.

**Release the state lock.**

### Wait, Take Over, or Start Loading

**No coordination lock is held.**

Prompt mode waits for Enter. With no observed operation, Enter starts loading. With an operation observed, Enter follows the takeover procedure below.

Immediate mode may start loading while other loaders are active, provided no exclusive clear blocks it. It does not read keyboard input in Keychain's waiting loop. Each loading child can then present its own OpenSSH prompt.

Notifications and lifetime closure return control to the protected check above. Checking a lock is not reserving an operation; other invocations may act before this terminal next acquires the state lock.

### Claim an Attempt and Publish It

**Acquire the state lock.**

Try the activation lock without blocking: shared for loading, exclusive for clearing. If unavailable, do not publish. If available, retain it and acquire this new attempt's exclusive lock.

Remove abandoned resources found through discovery. Create the attempt's lifetime and cancellation FIFOs, record `loading`, and send start notifications before starting a child. A registered loader excludes its own attempt from its observations.

**Release the state lock.** A successful owner retains the activation and per-attempt locks; an unsuccessful contender retries through its caller.

### Load Keys and Listen for Other Results

**The state lock is not held.** The owner retains both long-lived locks.

Recheck the missing keys. If nothing remains, complete successfully without starting `ssh-add`. Otherwise validate the selected agent, prepare commands and expected public fingerprints, and start the listener and child. Each child inherits the shared activation lock, its attempt lock, and the lifetime writer. Multiple commands within one attempt still run sequentially.

The listener handles cancellation and peer completion while the main thread waits for `ssh-add`. After another attempt ends, it runs `ssh-add -l` against its selected agent, with a one-second query timeout, to check whether every fingerprint in its loading request is now present. If so, it terminates its own redundant child, waits for exit, and treats the attempt as satisfied. It does not cancel an unrelated request merely because somebody else succeeded. Unknown fingerprints, an unavailable agent, and timed-out verification do not authorize cancellation.

The verification query is outside the state lock. If peer observation fails, report the error and leave this prompt running while continuing to listen for cancellation. The listener has a 0.5-second stop check; each pass may refresh attempt observations. It does not query the agent on that timer, only after a peer outcome. Ordinary waiting terminals sleep for events without that timer.

Cancellation sends termination to the owner's child, waits up to five seconds, then kills and reaps it if needed. Keychain never reads the passphrase. On completion or a handled exception, stop the listener and reap any unfinished child before final publication.

### Publish the Outcome and Release Ownership

**Acquire the state lock.** The owner still holds its activation and attempt locks.

Save `success`, `failed`, or `canceled` and send completion notifications. A failed final save still leads to resource cleanup.

**Release the owner's attempt-lock and activation-lock descriptors.** An inheriting process can retain those locks until its own descriptors close.

Close the lifetime and cancellation endpoints. Remove temporary attempt files when no inherited lifetime writer remains; otherwise preserve the attempt's discoverability.

**Release the state lock.**

### Evaluate the Outcome and Finish

**No coordination lock is held.**

A successfully completed load reports its requested confirmation and lifetime settings. An already-satisfied invocation does not claim it applied its own settings. Cancellation and takeover produce short notices, including in quiet mode; normal success/settings information follows the ordinary quiet policy.

A loader whose own child fails reports that failure; it does not automatically retry. Another terminal's failure does not fail an independent loading child. A waiting terminal checks the actual agent after notifications: if keys remain missing, prompt mode offers Enter again and immediate mode may attempt the remaining load.

A terminal canceled by takeover waits for the replacement operation rather than immediately creating a competing prompt. The handoff has a one-second grace period while no operation is active. Once a successor is observed, waiting follows its notifications and lifetime instead of a deadline. If the requester disappeared before starting anything, the canceled terminal can resume after the grace period.

Finally, close observation handles and remove this terminal's own notification FIFO. Cleanup does not rewrite JSON. After successful SSH handling, perform any requested native GPG warm-up outside this coordination mechanism unless startup options excluded it. The agent normally remains running for later shells.

## Takeover While Waiting

### Request Cancellation

**Acquire the state lock.**

Refresh the active-attempt observations and remember all attempts being asked to stop. Send each one's cancellation FIFO a request. If none remains active, proceed toward loading. If delivery fails, report that the request could not be moved and clear the pending takeover request.

**Release the state lock.**

### Wait for the Previous Requests to End

**No coordination lock is held while sleeping.**

Use the ordinary waiting loop, with its separate state-lock acquisitions, until all remembered attempts have ended. The initial response deadline is seven seconds, allowing five seconds for child termination plus time to complete publication and cleanup.

A timeout reports that moving the request has not yet completed; it does not grant ownership. Keep the pending attempt identifiers so a late response can finish the takeover without another Enter. Once those attempts disappear, start the replacement if keys are still needed and print a short notice. New immediate invocations may still start independently; takeover is not an exclusive reservation against future arrivals.

The canceled owners wait for the replacement. A successful replacement cancels any other live redundant loading requests through the normal peer-verification path.

## Differing Key Settings

Concurrent invocations may request different confirmation or lifetime settings. Keychain does not reject or reconcile that difference. Each completed successful load reports what it applied, for example:

```text
SSH key settings applied: confirmation required; lifetime 30 minutes.
```

OpenSSH can replace an identity's constraints when it adds that identity again. If two additions both finish, the later successful addition determines its resulting settings. Keychain cannot read those constraints back through the ordinary identity-listing interface. The summary describes that invocation's successful request, not a guarantee that another invocation will never change it.

When another attempt already supplied the required keys and Keychain cancels its own child, it reports that cancellation instead of claiming to have applied its requested settings. Use consistent startup settings when consistent constraints are required.

## Clearing SSH Identities

Standalone `wipe --ssh` selects an existing agent without starting one. Startup `--clear` runs after agent preparation and before the normal missing-key check. Both use the same attempt lifecycle as loading, but acquire the activation lock exclusively. They retry a busy lock subject to `--lockwait`; zero means one attempt. This deadline controls lock acquisition, not the agent's response time.

Clearing has no requested-key check, Enter prompt, or loading listener. It runs `ssh-add -D` outside the state lock, retains exclusive activation access until completion, then publishes an outcome. A wipe's success is not proof that a waiter's keys are present. Explicit GPG wiping is outside SSH coordination.

**Existing crash-handling limit:** The wiping child does not inherit its parent's locks or lifetime writer. If only Keychain is killed with `SIGKILL`, a surviving `ssh-add -D` could continue after the parent's locks are released. The inherited-descriptor protection for loading does not cover this clearing case.

## Failure, Cleanup, and Security

- An uncatchable termination closes the process's descriptors. A surviving loading child retains its inherited locks and lifetime writer. An old JSON record cannot retain ownership.
- Registration before publication receives queued messages. Registration after publication discovers live attempts from their locks and lifetime channels. A start message for an already-ended attempt is remembered even if discovery finds no live operation.
- Completion can be observed through a queued message or lifetime closure. The saved result is consulted only for the matching attempt. A newer result can overwrite an older outcome; actual key checks still determine whether this invocation is satisfied.
- Notifications reject symlinks, ordinary files, and FIFOs owned by another user. Coordination paths are derived from validated attempt identifiers, not filenames supplied in JSON.
- Partial discovery failure closes readers already opened. Publication and completion failures release this process's resources. Cleanup preserves inherited lifetime writers instead of hiding surviving children.
- Abandoned attempt files are removed only under the state lock after acquiring the attempt's lock. Dead notification FIFOs with no reader can be removed during notification.
- No state lock is held while sleeping, querying an agent, waiting for a passphrase, or terminating a child. Attempt and activation lock acquisitions made under the state lock are nonblocking, avoiding a circular wait with completion.
- `--no-lock` deliberately disables these coordination guarantees.

### macOS Lifetime Notification

Apple's FIFO implementation can clear the shared EOF indication after an empty read. Lifetime observers therefore use non-consuming readiness, never a read. Discovery establishes liveness using locks; cleanup checks readiness to decide whether to preserve a surviving writer's pathname. See [Apple's FIFO implementation](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/miscfs/fifofs/fifo_vnops.c), particularly `fifo_read`, `fifo_select`, and `fifo_close_internal`.

The pseudo-terminal test harness drains every terminal while waiting, including during interrupted exit, just as actual terminal windows do. It does not assume that the activation lock is free while another loader is legitimately active.

## Remaining Limits

The listener's verification query is bounded, but ordinary agent queries retain their existing behavior. A suspended agent or an agent waiting for graphical confirmation can still delay those queries. Such a query does not hold the state lock. A query after ownership acquisition holds shared activation access, so clearing waits while other loaders may proceed.

If Keychain is killed while its loading child survives, there is no living cancellation listener for that child. Prompt-mode takeover cannot finish while that child retains its attempt lock. Immediate mode can run another prompt, but cannot ask a dead parent to cancel the orphan. This implementation never kills a process merely because a saved PID claims it owns a prompt.

The tested OpenSSH child retains inherited descriptors. A wrapper or helper that closes or retains them differently can change lifetime behavior. Child cancellation controls `ssh-add`, not arbitrary descendants of an askpass program.

This is not a security boundary against the account owner. Unlinking a live lock file, deleting another invocation's FIFO, or deliberately holding resources can defeat normal coordination. Do not mix older and newer coordination implementations in the same active loading session.

## Review Map

Read `src/keychain/coordination.py` in this order:

1. `ActivationOwner.__enter__`: shared/exclusive access, per-attempt ownership, publication.
2. `ActivationCoordinator.observe`: live-attempt discovery and abandoned-file cleanup.
3. `ActivationOwner._run_child` and `_cancel_loop`: descriptor inheritance, child termination, peer verification.
4. `ActivationOwner.__exit__`: child cleanup, final publication, lock release.
5. `ActivationWaiter.wait` and `request_takeover`: terminal input, notifications, lifetime closure, handoff.

Then read `SshAgent.start` for agent selection and spawning, and `SshAddPlan.keys_available` for the bounded fingerprint query. In `main.py`, `_coordinate_ssh_keys` chooses prompt/immediate behavior and evaluates outcomes; `_try_activation` rechecks missing keys and reports settings. These callers do not manage JSON registrations or directly signal another terminal's child.

## Test Coverage

`tests/test_coordination.py` tests malformed and unreadable results, partial FIFO messages, unsafe paths, missing notifications, inherited locks, publication failure, discovery failures, cancellation failures, and cleanup. It includes non-consuming closure detection for several observers, death during discovery, unlocked agent queries, and continued cancellation after peer-monitoring failure.

`tests/test_immediate.py` covers all prompt/immediate combinations with real locks and controlled loading. Cases include partial key overlap, independent failures, quiet behavior, handoff, and late cancellation responses.

`tests/test_coordination_e2e.py` uses disposable encrypted keys, dedicated real agents, real `ssh-add` children, and pseudo-terminals. It covers hidden-terminal takeover with and without quiet, five concurrent immediate prompts, takeover of several loaders, terminal-echo restoration, partial requests, independent key loads, differing successful settings, wipe exclusion, abrupt death, surviving children, and damaged JSON. Every test owns its agent and cleans up only its own processes.

`tests/test_agents.py` verifies the load plan's fingerprint set, conservative behavior for unknown fingerprints, all-key verification, and the query timeout. `tests/test_debug_log.py` covers private append-only diagnostic records, concurrent writers, unsafe destinations, and preservation of machine-readable output. The real-process logging test also checks that an entered passphrase does not appear in the diagnostic log.
