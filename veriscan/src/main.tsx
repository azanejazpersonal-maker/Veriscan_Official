const root = document.getElementById('root');
if (root) {
  import('react-dom/client').then(({ createRoot }) => {
    import('./App').then(({ default: App }) => {
      createRoot(root).render(<App />);
    });
  });
}

export {};
