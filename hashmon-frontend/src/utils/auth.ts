export const getAccessToken = (): string | null => {
  return localStorage.getItem('access_token');
};

export const setAccessToken = (token: string) => {
  localStorage.setItem('access_token', token);
};

export const clearAccessToken = () => {
  localStorage.removeItem('access_token');
};
