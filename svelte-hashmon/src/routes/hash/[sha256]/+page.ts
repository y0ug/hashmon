import { getHashDetail } from '$lib/api';
import type { PageLoad } from './$types';

export const load: PageLoad = async ({ params }) => {
  let data = await getHashDetail(params.sha256);
  return { 'hash': data.hash }
}
