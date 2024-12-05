export interface HttpResp<T> {
  status: string; // "success" or "error"
  data: T | null;
  message: string;
}
