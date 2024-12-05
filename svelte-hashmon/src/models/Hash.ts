export interface HashStatus {
  sha256: string;
  filename: string;
  build_id: string;
  last_check_at: string; // ISO string
  providers: {
    [providerName: string]: boolean;
  };
  alerted_by?: string[];
}

export interface HashesResponse {
  hashes: HashStatus[];
}

export interface HashDetailResponse {
  hash: HashStatus;
}

export interface NewHash {
  sha256: string;
  filename: string;
  build_id: string;
}
