/** @type {import('next').NextConfig} */
const repoName = process.env.GITHUB_REPOSITORY?.split('/')[1] || 'Ravynel-Security';
const isGitHubPages = process.env.GITHUB_PAGES === 'true';
const configuredBasePath = process.env.NEXT_PUBLIC_SITE_BASE_PATH || '';
const basePath = configuredBasePath || (isGitHubPages ? `/${repoName}` : '');

const nextConfig = {
  output: 'export',
  trailingSlash: true,
  poweredByHeader: false,
  basePath,
  assetPrefix: basePath || undefined,
  images: {
    unoptimized: true
  }
};

export default nextConfig;
