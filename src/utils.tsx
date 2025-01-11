export class Utils {
    public static doesValueExist(value: any): boolean {
        return value !== undefined && value !== null && value !== '';
    }
      
    public static isValidEmail(email: any): boolean {
        try {
            const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            return emailPattern.test(email) && typeof email == 'string';
        } catch {
            return false;
        }
    }

    public static isValidPassword(password: any): boolean {
        try {
            const passwordPattern = /^(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*])(?=.*[A-Z]).{8,}$/;
            return passwordPattern.test(password) && typeof password == 'string';
        } catch {
            return false;
        }
    }

    public static isFullNameValid(name: any): boolean {
        try {
            const parts = name.trim().split(/\s+/);
    
            if (parts.length < 2) return false;
    
            const isValid = parts.every((part: any) => {
                if (part.length < 2) return false;
    
                return /^[a-zA-ZÀ-ÖØ-öø-ÿ'-]+$/.test(part);
            });
    
            return isValid && typeof name == 'string';;
        } catch {
            return false;
        }
    }

    public static isBigInt(value: any): boolean {
        try {
            BigInt(value); 
            return true; 
        } catch {
            return false;
        }
    }

    public static isNumber(value: string | number): boolean {
        try {
            const numberValue = Number(value);
            return !isNaN(numberValue) && Number.isInteger(numberValue);
        } catch (e) {
            return false;
        }
    }
    
}