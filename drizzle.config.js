import {defineConfig} from 'drizzle-kit'

export default defineConfig({
    schema: './src/data/schema.js',
    out: './src/data/migrations',
    dialect: 'sqlite',
    driver: 'd1-http',
})