export class Utils {
    public static doesValueExist(value: any): boolean {
        return value !== undefined && value !== null && value !== '';
    }
      
    public static isValidEmail(email: string): boolean {
        const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        return email.length <= 255 && emailPattern.test(email);
    }

    public static isValidPassword(password: string): boolean {
        const passwordPattern = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*])(?=.*[A-Z]).{8,}$/;
        return password.length <= 255 && passwordPattern.test(password);
    }
}