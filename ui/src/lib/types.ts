// Mirrors crates/briqwall-common/src/model.rs (serde's default externally tagged enums).

export type Mode = "Off" | "Relaxed" | "Balanced" | "Strict" | "Lockdown";
export type Access = "Block" | "Ask" | "Lan" | "Allow";
export type RuleAccess = "Auto" | "Block" | "Lan" | "Allow";
export type Category = "System" | "Lolbin" | "Installed" | "UserSpace" | "Pseudo";
export type Risk = "Low" | "Medium" | "High";
export type Direction = "Out" | "In";

export type Signature =
  | { Valid: { publisher: string; catalog: boolean } }
  | { Invalid: { code: number } }
  | "Unsigned"
  | "Unknown";

/** Why the automatic verdict is what it is (see crates/briqwall-common). */
export type Reason =
  | "Unknown"
  | "Kernel"
  | "System"
  | "Tool"
  | "ToolRelaxed"
  | "Installed"
  | "InstalledUnsignedStrict"
  | "InvalidSignature"
  | "Unsigned"
  | "MisplacedSystemFile"
  | { RiskyLocation: string }
  | { InstalledSigned: string }
  | { LearnedPublisher: string }
  | { KnownPublisher: string }
  | { SignedRelaxed: string }
  | { UnknownPublisher: string };

export type Location = "Downloads" | "Temp" | "Desktop" | "Public" | "AppData" | "ProgramFiles" | "UserProfile" | "Removable";
export type NetCategory = "Public" | "Private" | "Domain";

export interface UserRule {
  outbound: RuleAccess;
  inbound: RuleAccess;
  expires: number | null;
  created: number;
}

export interface AppInfo {
  key: string;
  path: string;
  name: string;
  signature: Signature;
  category: Category;
  protected: boolean;
  location_hint: Location | null;
  first_seen: number;
  last_seen: number;
  last_blocked: number | null;
  blocked_count: number;
  inbound_blocked_count: number;
  last_remote: string | null;
  /** Name looked up for the last blocked attempt (service keeps it in memory only). */
  last_host?: string | null;
  rule: UserRule | null;
  auto_out: Access;
  auto_in: Access;
  reason: Reason;
  effective_out: Access;
  effective_in: Access;
  risk: Risk;
  pending: boolean;
  snoozed_until: number | null;
  tampered: boolean;
  /** Process instances behind recent blocked attempts (newest first). */
  origins?: ProcessOrigin[];
}

export interface ParentProcess {
  pid: number;
  name: string;
  path: string | null;
}

export interface ProcessOrigin {
  pid: number;
  command_line: string | null;
  /** Parent first, then grandparent, … */
  parents: ParentProcess[];
  last_seen: number;
  count: number;
}

export interface Settings {
  mode: Mode;
  previous_mode: Mode;
  lan_discovery: boolean;
  learn_publishers: boolean;
  learned_publishers: string[];
  network_trust: Record<string, boolean>;
}

export interface NetworkInfo {
  id: string;
  name: string;
  windows_category: NetCategory;
  trusted: boolean;
  explicit: boolean;
}

export interface Status {
  version: string;
  mode: Mode;
  engine_ok: boolean;
  engine_error: string | null;
  privileged: boolean;
  networks: NetworkInfo[];
  network_trusted: boolean;
  apps_total: number;
  apps_allowed: number;
  apps_blocked: number;
  pending: number;
  blocked_session: number;
  started: number;
  revision: number;
  settings: Settings;
  /** Accounts with a Windows Hello key; an empty sid is a key from before per-account enrollment. */
  hello_users: HelloUser[];
}

export type EventKind =
  | { Blocked: { key: string; name: string; remote: string; host?: string | null; direction: Direction; by_rule: boolean } }
  | { NewRequest: { key: string; name: string; risk: Risk } }
  | { AutoAllowed: { key: string; name: string; reason: Reason } }
  | { RuleChanged: { key: string; name: string; rule: UserRule | null } }
  | { RuleExpired: { key: string; name: string } }
  | { Tampered: { key: string; name: string } }
  | { ModeChanged: { from: Mode; to: Mode } }
  | { NetworkChanged: { name: string; trusted: boolean } }
  | { Started: { version: string; mode: Mode } }
  | { PublisherLearned: { publisher: string } }
  | "HelloEnrolled"
  | "HelloRemoved"
  | { ApplyFailed: { detail: string } };

export interface XEvent {
  seq: number;
  time: number;
  kind: EventKind;
}

export type Request =
  | { SetMode: Mode }
  | { SetRule: { key: string; rule: UserRule | null } }
  | { Snooze: { key: string } }
  | { Forget: { key: string } }
  | { AddApp: { path: string } }
  | { SetNetworkTrust: { id: string; trusted: boolean | null } }
  | { SetOptions: { lan_discovery: boolean | null; learn_publishers: boolean | null } }
  | { RemovePublisher: string }
  | { RemoveHello: { sid: string } };

export interface HelloUser {
  sid: string;
  name: string;
}

export interface ConnState {
  connected: boolean;
  error: string | null;
  status: Status | null;
}

export interface Snapshot extends ConnState {
  apps: AppInfo[];
  events: XEvent[];
}

export interface UiPrefs {
  notifications: boolean;
  autostart: boolean;
  service_exe_available: boolean;
  /** "system", "de" or "en" */
  language: "system" | "de" | "en";
  /** What "system" resolves to. */
  system_language: "de" | "en";
  /** Windows account this UI runs as. */
  user_sid: string;
  user_name: string;
}

/** Outcome of picking a program in the file dialog. */
export type AddResult = { kind: "added"; key: string; existed: boolean } | { kind: "cancelled" } | { kind: "failed"; message: string };

/** Outcome of a change request (the backend retries via UAC when needed). */
export type ActionResult = { kind: "done" } | { kind: "cancelled" } | { kind: "failed"; message: string };
