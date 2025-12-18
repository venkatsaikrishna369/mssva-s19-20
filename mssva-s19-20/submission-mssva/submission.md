## Flag-1: FLAG1_CONF_WRITE

**Claim**  
IMD creates and uses `/tmp/important.conf` at runtime without protection, allowing external modification.

**Evidence**  
- File did not exist before IMD ran.  
- Created by IMD with content: `config=true`  
- Permissions: `0644` (world-readable).  
- Manual append succeeded (`ATTACK_TEST=1`).  
- File persisted after daemon exit.

**Reasoning**  
The daemon stores configuration in a public temp location with no integrity or ownership controls, enabling unauthorized edits.

**Security Impact**  
Attackers can alter IMD’s configuration and affect privileged behavior.

**Visibility Gap**  
Telemetry only confirms existence—not file ownership changes or write origin.


## Flag-2: FLAG2_HIDDEN_FORK

**Claim**  
IMD silently spawns a separate child process during execution, creating hidden runtime behaviour not indicated by normal daemon output or documentation.

**Evidence**  
- Live process tree shows two running IMD processes linked by parent-child relationship:
- PID 576 ./bin/imd
- PID 577 ./bin/imd (child, PPID=576)
- `pstree` confirmed:
- imd(576)---imd(577)

Both processes existed only while IMD was running, and both terminated when IMD was killed.

**Reasoning**  
A privileged daemon spawning an additional IMD process without logs or explanation indicates hidden execution paths or helper routines, increasing attack surface.

**Security Impact**  
An attacker could hide malicious activity inside the child, bypass monitoring, or exploit race conditions between parent and helper execution.

**Visibility Gap**  
Telemetry does not show parent/child mapping or explain why the fork occurs.


## Flag-3: FLAG3_INTERNAL_SOCKET

**Claim**  
IMD shows recurring internal TCP activity on `127.0.0.1:5555` even though no persistent listener or open socket is visible to the system.

**Evidence**  
- Telemetry repeatedly logs:  
  `Detected internal TCP activity on 127.0.0.1:5555`
- System inspection found no active port or listener:  
  `ss`, `netstat`, and `/proc/net/tcp` show nothing.
- Activity appears only during daemon runtime and disappears immediately.

**Reasoning**  
The daemon performs short-lived internal IPC over TCP, leaving no persistent socket footprint. This contradicts expectations for a privileged local service that is not supposed to expose network behavior.

**Security Impact**  
IMD may be exchanging sensitive data over an undocumented internal channel. Attackers with local access could exploit transient connections or race conditions to inject messages.

**Visibility Gap**  
Telemetry detects the activity, but the OS provides no socket details—no PID, no state, no duration.


## Flag-4: FLAG4_EXTERNAL_BINARY    

**Claim**  
IMD uses an external binary (`/bin/echo`) through a fork-and-exec pattern during runtime instead of internal code.

**Evidence**  
- Two IMD processes form a fork pair:
- 827 ./bin/imd
- 828 ./bin/imd (child)
- The child becomes a `<defunct>` process, indicating exec() transition.
- Telemetry environment documents `/bin/echo` execution as part of IMD behaviour.

**Reasoning**  
The zombie child proves the daemon forks and immediately execs into another binary. This confirms reliance on external executables rather than internal logic.

**Security Impact**  
External execution exposes IMD to command-injection or path-manipulation attacks if binary paths or arguments are influenced.

**Visibility Gap**  
The exec() is fast and leaves no persistent process footprint, making detection difficult.


## Flag-5: FLAG5_SECURE_WRITE

**Claim**  
IMD creates and maintains a sensitive data file `/tmp/secure_data` during runtime.

**Evidence**  
- The file exists only while IMD runs:
- /tmp/secure_data → SECRET=XYZ
- Permissions show restricted access: `0600`
- Manual edit succeeded (`TEST` appended) and persisted.
- File remains after IMD stops.

**Reasoning**  
IMD stores internal secrets in a temporary location not tied to daemon lifecycle or secure storage mechanisms.

**Security Impact**  
Secrets written to `/tmp` enable leakage, backup exposure, and post-shutdown data harvesting.

**Visibility Gap**  
Telemetry confirms the artifact exists but not what data is stored or how it’s used.