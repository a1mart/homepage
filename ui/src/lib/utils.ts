// lib/utils.ts (extend the existing one)
import { type ClassValue, clsx } from 'clsx';
import { twMerge } from 'tailwind-merge';

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatUptime(uptime: string): string {
  return uptime;
}

export function formatBytes(bytes: number): string {
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  if (bytes === 0) return '0 Bytes';
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return Math.round((bytes / Math.pow(1024, i)) * 100) / 100 + ' ' + sizes[i];
}

export function getStatusColor(status: string): string {
  switch (status) {
    case 'online':
    case 'Ready':
      return 'text-green-400';
    case 'offline':
    case 'NotReady':
      return 'text-red-400';
    case 'checking':
    case 'Unknown':
      return 'text-yellow-400';
    default:
      return 'text-gray-400';
  }
}

export function getSeverityColor(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'text-red-400 bg-red-500/20 border-red-500/30';
    case 'warning':
      return 'text-yellow-400 bg-yellow-500/20 border-yellow-500/30';
    case 'info':
      return 'text-blue-400 bg-blue-500/20 border-blue-500/30';
    default:
      return 'text-gray-400 bg-gray-500/20 border-gray-500/30';
  }
}
