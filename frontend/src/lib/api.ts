import axios from 'axios';
import type { BuildConfig, BuildJob, ApiResponse, ClientListItem, ClientDetail, ProfileDetail, ClientListItem as CLItem } from '@/types';

const api = axios.create({
  baseURL: '/api',
  headers: {
    'Content-Type': 'application/json',
  },
});

// Add auth token if available
api.interceptors.request.use((config) => {
  if (typeof window !== 'undefined') {
    const token = localStorage.getItem('rdgen_token');
    if (token) {
      config.headers['X-Session-Token'] = token;
    }
  }
  return config;
});

export async function startBuild(config: BuildConfig): Promise<ApiResponse<BuildJob>> {
  try {
    const response = await api.post<ApiResponse<BuildJob>>('/build', config);
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'Failed to start build',
    };
  }
}

export async function getBuildStatus(jobId: string): Promise<ApiResponse<BuildJob>> {
  try {
    const response = await api.get<ApiResponse<BuildJob>>(`/status/${jobId}`);
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'Failed to get build status',
    };
  }
}

export async function getArtifactUrl(jobId: string): Promise<ApiResponse<{ url: string }>> {
  try {
    const response = await api.get<ApiResponse<{ url: string }>>(`/artifact/${jobId}`);
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'Failed to get artifact URL',
    };
  }
}

export async function listJobs(): Promise<ApiResponse<BuildJob[]>> {
  try {
    const response = await api.get<ApiResponse<BuildJob[]>>('/jobs');
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'Failed to list jobs',
    };
  }
}

export async function cancelBuild(jobId: string): Promise<ApiResponse<void>> {
  try {
    const response = await api.post<ApiResponse<void>>(`/cancel/${jobId}`);
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'Failed to cancel build',
    };
  }
}

export async function uploadIcon(file: File): Promise<ApiResponse<{ base64: string }>> {
  try {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post<ApiResponse<{ base64: string }>>('/upload/icon', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'Failed to upload icon',
    };
  }
}

export async function uploadLogo(file: File): Promise<ApiResponse<{ base64: string }>> {
  try {
    const formData = new FormData();
    formData.append('file', file);
    const response = await api.post<ApiResponse<{ base64: string }>>('/upload/logo', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'Failed to upload logo',
    };
  }
}

export async function healthCheck(): Promise<ApiResponse<{ status: string }>> {
  try {
    const response = await api.get<ApiResponse<{ status: string }>>('/health');
    return response.data;
  } catch (error: any) {
    return {
      success: false,
      error: error.response?.data?.error || error.message || 'API is not available',
    };
  }
}

// =====================
// Client & Profile API
// =====================

export async function listClients(): Promise<ApiResponse<ClientListItem[]>> {
  try {
    const response = await api.get<ApiResponse<ClientListItem[]>>('/clients');
    return response.data;
  } catch (error: any) {
    return { success: false, error: error.response?.data?.error || error.message };
  }
}

export async function getClient(clientId: string): Promise<ApiResponse<ClientDetail>> {
  try {
    const response = await api.get<ApiResponse<ClientDetail>>(`/clients/${clientId}`);
    return response.data;
  } catch (error: any) {
    return { success: false, error: error.response?.data?.error || error.message };
  }
}

export async function createClient(name: string): Promise<ApiResponse<ClientDetail>> {
  try {
    const response = await api.post<ApiResponse<ClientDetail>>('/clients', { name });
    return response.data;
  } catch (error: any) {
    return { success: false, error: error.response?.data?.error || error.message };
  }
}

export async function renameClient(clientId: string, name: string): Promise<ApiResponse<ClientDetail>> {
  try {
    const response = await api.patch<ApiResponse<ClientDetail>>(`/clients/${clientId}`, { name });
    return response.data;
  } catch (error: any) {
    return { success: false, error: error.response?.data?.error || error.message };
  }
}

export async function deleteClient(clientId: string): Promise<ApiResponse<void>> {
  try {
    const response = await api.delete<ApiResponse<void>>(`/clients/${clientId}`);
    return response.data;
  } catch (error: any) {
    return { success: false, error: error.response?.data?.error || error.message };
  }
}

export async function createProfile(
  clientId: string, profileName: string, host: string, platform: string, config: BuildConfig
): Promise<ApiResponse<ProfileDetail>> {
  try {
    const response = await api.post<ApiResponse<ProfileDetail>>(`/clients/${clientId}/profiles`, {
      profileName, host, platform, config,
    });
    return response.data;
  } catch (error: any) {
    return { success: false, error: error.response?.data?.error || error.message };
  }
}

export async function addProfileVersion(
  clientId: string, profileId: string, config: BuildConfig
): Promise<ApiResponse<ProfileDetail>> {
  try {
    const response = await api.put<ApiResponse<ProfileDetail>>(
      `/clients/${clientId}/profiles/${profileId}`, { config }
    );
    return response.data;
  } catch (error: any) {
    return { success: false, error: error.response?.data?.error || error.message };
  }
}

export async function getProfileVersion(
  clientId: string, profileId: string, versionId: string
): Promise<ApiResponse<BuildConfig>> {
  try {
    const response = await api.get<ApiResponse<BuildConfig>>(
      `/clients/${clientId}/profiles/${profileId}/versions/${versionId}`
    );
    return response.data;
  } catch (error: any) {
    return { success: false, error: error.response?.data?.error || error.message };
  }
}

export async function renameProfile(
  clientId: string, profileId: string, name: string
): Promise<ApiResponse<ProfileDetail>> {
  try {
    const response = await api.patch<ApiResponse<ProfileDetail>>(
      `/clients/${clientId}/profiles/${profileId}`, { name }
    );
    return response.data;
  } catch (error: any) {
    return { success: false, error: error.response?.data?.error || error.message };
  }
}

export async function deleteProfile(clientId: string, profileId: string): Promise<ApiResponse<void>> {
  try {
    const response = await api.delete<ApiResponse<void>>(`/clients/${clientId}/profiles/${profileId}`);
    return response.data;
  } catch (error: any) {
    return { success: false, error: error.response?.data?.error || error.message };
  }
}
