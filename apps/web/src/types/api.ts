// Type definitions for API responses

export interface UserResponse {
  id: string;
  email: string;
  full_name: string | null;
  role: 'ADMIN' | 'INVESTIGATOR' | 'DEVELOPER' | 'VIEWER';
  organization_id: string;
}

export interface OrganizationResponse {
  id: string;
  name: string;
  slug: string;
}

export interface ToolResponse {
  id: string;
  name: string;
  description: string | null;
  author_id: string;
  created_at: string;
  updated_at: string;
  versions: ToolVersionResponse[];
}

export interface ToolVersionResponse {
  id: string;
  version: string;
  source_hash: string;
  compiler_version: string;
  target_platform: string;
  target_arch: string;
  capabilities: string[];
  artifact_hash: string | null;
  artifact_size: number | null;
  is_published: boolean;
  published_at: string | null;
  created_at: string;
  updated_at: string;
  compiler_hash: string | null;
}

export interface InvestigationResponse {
  id: string;
  name: string;
  description: string | null;
  tool_version_id: string | null;
  status: 'draft' | 'running' | 'completed' | 'failed';
  created_by: string;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface EvidenceResponse {
  id: string;
  investigation_id: string;
  tool_version_id: string | null;
  host_identifier: string | null;
  collection_time: string;
  sha256_hash: string;
  size_bytes: number;
  storage_path: string;
  metadata: Record<string, unknown> | null;
  merkle_proof: Record<string, unknown> | null;
  created_at: string;
}

export interface BuildResponse {
  id: string;
  tool_version_id: string;
  status: 'pending' | 'running' | 'success' | 'failed';
  build_log: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface AuditLogResponse {
  id: string;
  organization_id: string;
  user_id: string | null;
  action: string;
  resource_type: string | null;
  resource_id: string | null;
  result: 'success' | 'failure';
  ip_address: string | null;
  user_agent: string | null;
  metadata: Record<string, unknown> | null;
  created_at: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: {
    page: number;
    per_page: number;
    total: number;
  };
}

export interface ErrorResponse {
  error: string;
  message: string;
  code: string | null;
  request_id: string | null;
}

// Request types
export interface CreateToolRequest {
  name: string;
  description?: string;
  project_id?: string;
}

export interface CreateToolVersionRequest {
  version: string;
  source: string;
  target_platform: string;
  target_arch: string;
}

export interface BuildToolRequest {
  target_platform?: string;
  target_arch?: string;
}

export interface CreateInvestigationRequest {
  name: string;
  description?: string;
  project_id?: string;
  tool_version_id?: string;
}

export interface UploadEvidenceRequest {
  investigation_id: string;
  tool_version_id?: string;
  host_identifier?: string;
  collection_time: string;
  metadata?: Record<string, unknown>;
}