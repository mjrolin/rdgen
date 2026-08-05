/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  async rewrites() {
    return [
      {
        source: '/api/:path*',
        destination: 'http://127.0.0.1:4000/api/:path*',
      },
      {
        source: '/swagger-api',
        destination: 'http://127.0.0.1:4000/api-docs',
      },
      {
        source: '/swagger.json',
        destination: 'http://127.0.0.1:4000/swagger.json',
      },
    ];
  },
};

module.exports = nextConfig;
