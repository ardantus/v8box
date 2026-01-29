import type { LibSQLClient, Redis, S3ClientType } from "./deps.ts";

// Service Context injected into Workers
export interface ServiceContext {
    db: LibSQLClient;
    cache: Redis;
    s3: S3ClientType;
}

// Worker Function Signature
export type WorkerFunction = (ctx: ServiceContext, params?: Record<string, unknown>) => Promise<unknown> | unknown;

// Admin Session
export interface AdminSession {
    authenticated: boolean;
    timestamp: number;
}

// API Response Types
export interface ApiResponse<T = unknown> {
    success: boolean;
    data?: T;
    error?: string;
    timestamp?: number;
}

// Worker Execution Log
export interface ExecutionLog {
    timestamp: string;
    status: "success" | "error";
    duration: number;
    error?: string;
}

// File Info
export interface FileInfo {
    name: string;
    size: number;
    modified: Date;
}

// Page Project Info
export interface PageProject {
    name: string;
    path: string;
    files: number;
}

// S3 Object Info
export interface S3Object {
    key: string;
    size: number;
    lastModified?: Date;
}
