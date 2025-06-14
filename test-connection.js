const { PrismaClient } = require('@prisma/client');
const Redis = require('redis');

async function testConnections() {
  console.log('Testing database connection...');
  
  try {
    const prisma = new PrismaClient({
      datasources: {
        db: {
          url: 'postgresql://postgres:postgres@localhost:5432/tekparola'
        }
      }
    });
    
    await prisma.$connect();
    console.log('✅ Database connection successful');
    await prisma.$disconnect();
  } catch (error) {
    console.error('❌ Database connection failed:', error.message);
  }
  
  console.log('Testing Redis connection...');
  try {
    const redis = Redis.createClient({
      url: 'redis://localhost:6379'
    });
    
    await redis.connect();
    await redis.ping();
    console.log('✅ Redis connection successful');
    await redis.disconnect();
  } catch (error) {
    console.error('❌ Redis connection failed:', error.message);
  }
}

testConnections().catch(console.error);