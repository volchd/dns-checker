export interface DKIMValidationResult {
  selector: string;
  domain: string;
  valid: boolean;
  error?: string;
  record?: string;
}
