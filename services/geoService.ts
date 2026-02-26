
export interface GeoData {
  location: string;
  lat?: number;
  lng?: number;
}

const geoCache: Record<string, GeoData> = {
  '127.0.0.1': { location: 'Localhost' },
  '192.168.1.1': { location: 'Local Network' },
};

export const fetchGeolocation = async (ip: string): Promise<GeoData> => {
  if (geoCache[ip]) return geoCache[ip];

  // Skip private IPs
  if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.')) {
    return { location: 'Private Network' };
  }

  try {
    const response = await fetch(`https://ipwho.is/${ip}`);
    if (!response.ok) throw new Error('Geo API error');
    const data = await response.json();
    
    if (!data.success) return { location: 'Unknown' };
    
    const location = `${data.city || ''}${data.city && data.country ? ', ' : ''}${data.country || ''}` || 'Unknown';
    const geoData = {
      location,
      lat: data.latitude,
      lng: data.longitude
    };
    geoCache[ip] = geoData;
    return geoData;
  } catch (error) {
    return { location: 'Unknown' };
  }
};
