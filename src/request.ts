export interface LoginUser {
    email: string,
    password: string,
}

export interface CreateUser {
    fullName: string
    email: string,
    password: string,
}

export interface UpdateUser {
    fullName?: string,
    email?: string
}

export interface NewPasswordUser {
    email: string,
    password: string,
    newPassword: string
}

export interface CreateTrip {
    userId: bigint,
    tripName: string,
    period: string,
    daysQty: number,
    currency: string,
    budgetAmount: number,
    season: string, 
    spent: number,
    notes: string
}

export interface UpdateTrip {
    id: BigInt,
    userId: bigint,
    tripName?: string,
    period?: string,
    daysQty?: number,
    currency?: string,
    budgetAmount?: number,
    season?: string, 
    spent?: number
    notes?: string
}

export interface TokenContent {
    id: bigint,
    email: string,
}