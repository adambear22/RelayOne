import { request, requestPaginated } from './client'
import type { PaginatedResult } from '../types/api'
import type { Announcement } from '../types/models'

export async function listActiveAnnouncements() {
  return request<Announcement[]>({
    method: 'GET',
    url: '/announcements/active',
  })
}

export interface ListAnnouncementsParams {
  page?: number
  page_size?: number
}

export interface SaveAnnouncementPayload {
  type: string
  title: string
  content: string
  is_enabled?: boolean
  starts_at?: string
  ends_at?: string
}

export async function listAnnouncements(params?: ListAnnouncementsParams): Promise<PaginatedResult<Announcement[]>> {
  return requestPaginated<Announcement[]>({
    method: 'GET',
    url: '/announcements',
    params,
  })
}

export async function createAnnouncement(payload: SaveAnnouncementPayload) {
  return request<Announcement>({
    method: 'POST',
    url: '/announcements',
    data: payload,
  })
}

export async function updateAnnouncement(id: string, payload: Partial<SaveAnnouncementPayload>) {
  return request<Announcement>({
    method: 'PUT',
    url: `/announcements/${id}`,
    data: payload,
  })
}

export async function toggleAnnouncement(id: string, enabled: boolean) {
  return request<Announcement>({
    method: 'PATCH',
    url: `/announcements/${id}/toggle`,
    data: { enabled },
  })
}

export async function deleteAnnouncement(id: string) {
  return request<{ deleted: boolean }>({
    method: 'DELETE',
    url: `/announcements/${id}`,
  })
}
