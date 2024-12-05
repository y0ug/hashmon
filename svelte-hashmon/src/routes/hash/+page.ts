import type { PageLoad } from './$types';
import { getAllHashes } from '$lib/api';

export const load: PageLoad = async ({ params }) => {
  return await getAllHashes()
};
