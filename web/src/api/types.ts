// Shapes of the API's JSON. They mirror the C# records in src/ThreatLock.Api; in a later
// milestone these are generated from the OpenAPI document instead of written by hand (SPEC §13).

export interface UserView {
  id: string
  email: string
  displayName: string
  orgId: string
  orgName: string
  orgSlug: string
  roles: string[]
}

export interface LoginResponse {
  accessToken: string
  expiresAt: string
  user: UserView
}

export interface NoteSummary {
  id: string
  title: string
  shared: boolean
  isOwner: boolean
  ownerName: string
  updatedAt: string
}

export interface NoteView extends NoteSummary {
  body: string
  createdAt: string
}

export interface NoteRequest {
  title: string
  body: string
  shared: boolean
}
