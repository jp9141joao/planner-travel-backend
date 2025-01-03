export interface LoginUser {
    email: string,
    password: string,
}

export interface CreateUser {
    fullName: string
    email: string,
    password: string,
    imageProfile?: string
}

export interface UpdateUser {
    fullName?: string,
    email?: string
    imageProfile?: string
}

export interface NewPasswordUser {
    email: string,
    password: string,
    newPassword: string
}