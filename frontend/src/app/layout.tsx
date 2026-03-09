import type { Metadata } from 'next';
import { Toaster } from 'react-hot-toast';
import './globals.css';
import AuthGuard from '@/components/AuthGuard';

export const metadata: Metadata = {
  title: 'RDGen - RustDesk Custom Client Builder',
  description: 'Build custom RustDesk clients with your own branding and configuration',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <head>
        <link
          href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&display=swap"
          rel="stylesheet"
        />
        <link
          rel="stylesheet"
          href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css"
        />
      </head>
      <body className="min-h-screen bg-black text-gray-200">
        <Toaster
          position="top-right"
          toastOptions={{
            style: {
              background: '#222',
              color: '#fff',
              border: '1px solid #444',
            },
          }}
        />
        <AuthGuard>
          {children}
        </AuthGuard>
      </body>
    </html>
  );
}
