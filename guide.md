+ How to init node js project with Tsx
    1. npm init -y
    2. src/index.
    3. config nodemon auto restart whenever saving (npm install -D @types/nodemon)
        "start": "nodemon --exec tsx src/index.ts"
    4. # Install TypeScript, Node types, and tsx as dev dependencies
        npm install -D typescript tsx @types/node
    5. Configure TypeScript (Generate a tsconfig.json configuration file)
        npx tsc --init
    6. Add to "compilerOptions"
        "moduleResolution": "NodeNext",
        "esModuleInterop": true,
    7. Configure Scripts in package.json
        "scripts": {
            "dev": "tsx watch src/index.ts",
            "start": "tsx src/index.ts"
        }

+ Connect DB with Supabase
  1. npm install @supabase/supabase-js
  2. src/cofig/db.ts
        
    



