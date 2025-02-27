export class HttpResult<T> {
    public success: boolean;
    public data: T | null;
    public error: string | { details: string, at?: string };
  
    private constructor(success: boolean, data: T | null, error: string | { details: string, at?: string }) {
      this.success = success;
      this.data = data;
      this.error = error;
    }
  
    public static Success<T>(data: T | null = null): HttpResult<T> {
      return new HttpResult<T>(true, data, { details: "", at: "" });
    }
  
    public static Fail(error: string | { details: string, at?: string },): HttpResult<any> {
      return new HttpResult<any>(false, null, error);
    }
  }
  