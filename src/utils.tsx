export class Utils {
    public static doesValueExist(value: any): boolean {
        return value !== undefined && value !== null && value !== '';
    }
      
    public static isValidEmail(email: string): boolean {
        try {
            const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            return emailPattern.test(email);
        } catch {
            return false;
        }
    }

    public static isValidPassword(password: string): boolean {
        try {
            const passwordPattern = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*])(?=.*[A-Z]).{8,}$/;
            return passwordPattern.test(password);
        } catch {
            return false;
        }
    }

    public static isFullNameValid(name: string): boolean {
        try {
            const parts = name.trim().split(/\s+/);
    
            if (parts.length < 2) return false;
    
            const isValid = parts.every(part => {
                if (part.length < 2) return false;
    
                return /^[a-zA-ZÀ-ÖØ-öø-ÿ'-]+$/.test(part);
            });
    
            return isValid;
        } catch {
            return false;
        }
    }
    
}