import axios from 'axios';

const API = axios.create({ baseURL: 'http://localhost:8000/api' });

export const seedDatabase  = ()  => API.post('/ingest/seed');
export const runEngines    = ()  => API.post('/analytics/run');
export const getStatus     = ()  => API.get('/ingest/status');
export const getKPIs       = ()  => API.get('/dashboard/kpis');
export const getMTTR       = ()  => API.get('/dashboard/mttr-distribution');
export const getHeatmap    = ()  => API.get('/dashboard/cse-heatmap');
export const getTimeline   = ()  => API.get('/dashboard/alert-timeline');
export const getFeed       = ()  => API.get('/dashboard/findings-feed');
export const getFindings   = (params?: Record<string, string>) => API.get('/analytics/findings', { params });
export const getSummary    = ()  => API.get('/analytics/summary');
