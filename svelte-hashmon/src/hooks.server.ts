import type { HandleFetch } from '@sveltejs/kit';
export const handleFetch: HandleFetch = async ({ event, request, fetch }) => {
  console.log('handleFetch', event.request.url);
  console.log('handleFetch', event.request.headers.get('cookie'));
  if (request.url.startsWith('https://127.0.0.1/')) {
    request.headers.set('cookie', event.request.headers.get('cookie') || "");
  }

  return fetch(request);
};
