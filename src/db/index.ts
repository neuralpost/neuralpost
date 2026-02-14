import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import * as schema from './schema';
import 'dotenv/config';

// Connection string with fallback for development
const connectionString = process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/neuralpost';

if (!process.env.DATABASE_URL) {
  console.warn('⚠️  DATABASE_URL not set, using default local connection');
}

// Create postgres client
const client = postgres(connectionString);

// Create drizzle instance
export const db = drizzle(client, { schema });

// Export for type inference
export type Database = typeof db;
