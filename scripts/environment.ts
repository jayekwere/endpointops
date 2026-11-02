import { demoAuth } from '../src/security.js';
import { Store } from '../src/store.js';
import { createApp } from '../src/app.js';
import { seed } from '../src/lab.js';
export async function environment(baseUrl = 'http://127.0.0.1:4420') {
  const { auth, tokens } = await demoAuth('endpointops'),
    store = new Store(':memory:', 'k'.repeat(32));
  const { app, service } = createApp({ auth, store, baseUrl });
  seed(service, store.now());
  return {
    app,
    service,
    store,
    auth,
    tokens,
    close: async () => {
      await app.close();
      store.close();
    },
  };
}
