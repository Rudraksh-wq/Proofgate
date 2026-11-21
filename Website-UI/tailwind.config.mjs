/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  theme: {
    extend: {
      colors: {
        yellow: '#ffe17c',
        charcoal: '#171e19',
        sage: '#b7c6c2',
        white: '#ffffff',
        black: '#000000',
        darkgray: '#272727',
        lightgray: '#f4f4f5',
        status: { red: '#ff5f57', amber: '#ffbc2e', green: '#28c840' },
      },
      boxShadow: {
        'hard-4': '4px 4px 0 0 #000',
        'hard-8': '8px 8px 0 0 #000',
        'hard-12': '12px 12px 0 0 #000',
      },
      fontFamily: {
        heading: ['Cabinet Grotesk', 'system-ui', 'sans-serif'],
        body: ['Satoshi', 'system-ui', 'sans-serif'],
      },
      letterSpacing: { tighter: '-.05em' },
      borderWidth: { 2: '2px' },
      borderRadius: { brutal: '12px' },
    },
  },
  plugins: [],
};
