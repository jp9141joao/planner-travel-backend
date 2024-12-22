export interface CreateUser {
    fullName: string
    email: string,
    password: string,
    imageProfile: string
}

export interface UpdateUser {
    fullName?: string,
    email?: string
    imageProfile?: string
}