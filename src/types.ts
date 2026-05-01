export interface Packet {
  id: string;
  timestamp: number;
  sourceIp: string;
  destIp: string;
  destPort: number;
  protocol: "TCP" | "UDP" | "ICMP" | "ARP";
  flags?: string[];
  payloadSize: number;
}

export interface Alert {
  id: string;
  timestamp: number;
  type: string;
  sourceIp: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM";
  description: string;
}

export interface AuthState {
  token: string | null;
  username: string | null;
}
