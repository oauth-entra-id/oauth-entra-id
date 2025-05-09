import axios from 'axios';

export const axiosFetch = axios.create({
  // baseURL: env.VITE_SERVER_URL, //in real usage, you will set the base URL here
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});
