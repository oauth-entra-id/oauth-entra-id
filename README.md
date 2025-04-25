# 🧙🏽‍♂️ OAuth Entra ID Monorepo 🧙🏽‍♂️

## Overview 🪟

A Monorepo that aims to provide a full-stack solution for authentication and authorization using our `oauth-entra-id` package which securely implements OAuth 2.0 to connect with Microsoft Entra ID. 🎉

## What's Inside? 🤔

### The Package! 📦

- [oauth-entra-id](packages/oauth-entra-id/) 💯 - Secure and simple package that provides all utilities needed for OAuth 2.0 with Entra ID for all types of NodeJS server frameworks. Read more about the package in [README](packages/oauth-entra-id/README.md).

### Demo Apps 🚀

- [React Demo App](demos/client-react/) 🖥️ - A [React](https://reactjs.org/) app that demonstrates how the frontend should behave with a backend-driven OAuth 2.0 authentication flow.
- [Express Demo App](demos/server-express/) 📫- An [Express](https://expressjs.com/) app that implements `oauth-entra-id/express` for authentication.
- [NestJS Demo App](demos/server-nestjs/) 🪺 - A [NestJS](https://nestjs.com/) app that implements `oauth-entra-id/nestjs` for authentication.
- [HonoJS Demo App](demos/server-honojs/) 🔥 - A [HonoJS](https://honojs.com/) app that implements authentication using the core utilities of the package.
- [Fastify Demo App](demos/server-fastify/) 🚀 - A [Fastify](https://www.fastify.io/) app that implements authentication using the core utilities of the package.

#### Extra Features 🎁

All server apps include the following features:

- **HTTP Security Headers** - Sets security headers to protect against common web vulnerabilities.
- **Rate Limiting** - Limits the number of requests a user can make to the server.
- **Logging** - Logs all requests to the server, with the user's IP address and request method.
- **Error Handling** - Handles errors gracefully and returns a user-friendly error message, while hiding sensitive information.
- **Environment Variables Handling** - Loads environment variables from a `.env` file and provides validates them.

## How Does Our Flow Work? 🌊

![oauth-entra-id-flow](./assets/oauth-entra-id-flow.png)

## How to Run the Project Locally 🚀

### _Setup_ 🛠️

Make sure you have [Node.js](https://nodejs.org/) installed on your machine.

The project uses [PNPM](https://pnpm.io/) as the package manager. PNPM can be installed by running:

```bash
npm install -g pnpm
```

Then you can install the dependencies:

```bash
pnpm install
```

You will need to set up environment variables in several places:

- `.env`
- `apps/client-react/.env`

