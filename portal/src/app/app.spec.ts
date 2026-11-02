import { TestBed } from '@angular/core/testing';
import { provideHttpClient } from '@angular/common/http';
import { HttpTestingController, provideHttpClientTesting } from '@angular/common/http/testing';
import { App } from './app';

describe('App', () => {
  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [App],
      providers: [provideHttpClient(), provideHttpClientTesting()],
    })
      .compileComponents();
  });

  it('should create the app', () => {
    const fixture = TestBed.createComponent(App);
    const app = fixture.componentInstance;
    expect(app).toBeTruthy();
  });

  it('should render title', async () => {
    const fixture = TestBed.createComponent(App);
    fixture.detectChanges();
    TestBed.inject(HttpTestingController)
      .expectOne((request) => request.url.endsWith('/v1/me'))
      .flush({}, { status: 401, statusText: 'Unauthorized' });
    await fixture.whenStable();
    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.querySelector('h1')?.textContent).toContain('Conecta tus servicios');
  });

  it('should show pending organization requests only after platform admin authentication', async () => {
    const fixture = TestBed.createComponent(App);
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();

    http.expectOne((request) => request.url.endsWith('/v1/me'))
      .flush({ role: 'platform_admin' });
    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations'))
      .flush({
        organizations: [
          {
            id: 'pending-org',
            name: 'Pendiente',
            status: 'pending',
            api_enabled: false,
            created_at: '2026-11-01T00:00:00.000Z',
            member_count: 1,
            application_count: 0,
          },
          {
            id: 'active-org',
            name: 'Activa',
            status: 'active',
            api_enabled: true,
            created_at: '2026-10-01T00:00:00.000Z',
            member_count: 2,
            application_count: 1,
          },
        ],
      });
    http.expectOne((request) => request.url.endsWith('/v1/admin/usage/summary'))
      .flush({ today: 0, last_7_days: 0, this_month: 0, errors: 0, requests: [] });

    fixture.detectChanges();
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(compiled.textContent).toContain('Administración de organizaciones');
    expect(Array.from(compiled.querySelectorAll('.admin-org-details strong')).map((item) => item.textContent?.trim()))
      .toEqual(['Pendiente']);
    http.verify();
  });

  it('should show newly submitted organizations after refreshing the admin list', async () => {
    const fixture = TestBed.createComponent(App);
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();

    http.expectOne((request) => request.url.endsWith('/v1/me'))
      .flush({ role: 'platform_admin' });
    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations'))
      .flush({ organizations: [] });
    http.expectOne((request) => request.url.endsWith('/v1/admin/usage/summary'))
      .flush({ today: 0, last_7_days: 0, this_month: 0, errors: 0, requests: [] });

    fixture.detectChanges();
    const refreshButton = fixture.nativeElement.querySelector('.admin-panel-heading button') as HTMLButtonElement;
    refreshButton.click();

    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations'))
      .flush({
        organizations: [{
          id: 'new-org',
          name: 'Nueva organización',
          status: 'pending',
          api_enabled: false,
          created_at: '2026-11-02T00:00:00.000Z',
          member_count: 1,
          application_count: 0,
        }],
      });
    http.expectOne((request) => request.url.endsWith('/v1/admin/usage/summary'))
      .flush({
        today: 1,
        last_7_days: 1,
        this_month: 1,
        errors: 0,
        requests: [{
          id: '1',
          organization_name: 'Nueva organización',
          application_name: 'Portal comercio',
          origin_domain: 'comercio.example',
          endpoint: '/v1/integrations/ping',
          method: 'POST',
          status_code: 200,
          duration_ms: 18,
          created_at: '2026-11-02T00:00:00.000Z',
        }],
      });

    fixture.detectChanges();
    await fixture.whenStable();

    const compiled = fixture.nativeElement as HTMLElement;
    expect(Array.from(compiled.querySelectorAll('.admin-org-details strong')).map((item) => item.textContent?.trim()))
      .toEqual(['Nueva organización']);
    expect(compiled.querySelector('.admin-requests-table')?.textContent)
      .toContain('comercio.example');
    expect(compiled.querySelector('.admin-requests-table')?.textContent)
      .toContain('Portal comercio');
    expect(compiled.querySelector('.admin-requests-table')?.textContent)
      .toContain('/v1/integrations/ping');
    http.verify();
  });

  it('persists organization and application API access changes and reflects key revocation', async () => {
    const fixture = TestBed.createComponent(App);
    const http = TestBed.inject(HttpTestingController);
    fixture.detectChanges();

    http.expectOne((request) => request.url.endsWith('/v1/me'))
      .flush({ role: 'platform_admin' });
    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations'))
      .flush({
        organizations: [{
          id: 'org-id',
          name: 'Comercio',
          status: 'active',
          api_enabled: false,
          created_at: '2026-11-01T00:00:00.000Z',
          member_count: 1,
          application_count: 1,
        }],
      });
    http.expectOne((request) => request.url.endsWith('/v1/admin/usage/summary'))
      .flush({ today: 0, last_7_days: 0, this_month: 0, errors: 0, requests: [] });
    fixture.detectChanges();

    const buttonByText = (text: string) => Array.from(
      (fixture.nativeElement as HTMLElement).querySelectorAll('button'),
    ).find((button) => button.textContent?.trim() === text) as HTMLButtonElement;

    buttonByText('Todas').click();
    fixture.detectChanges();
    buttonByText('Habilitar API').click();
    const organizationAccess = http.expectOne((request) => request.url.endsWith('/v1/admin/organizations/org-id/api-access'));
    expect(organizationAccess.request.body).toEqual({ enabled: true });
    organizationAccess.flush({ id: 'org-id', api_enabled: true });
    fixture.detectChanges();
    expect(buttonByText('Deshabilitar API')).toBeTruthy();

    buttonByText('Aplicaciones y claves').click();
    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations/org-id/applications'))
      .flush({
        applications: [{
          id: 'app-id',
          name: 'Portal comercio',
          environment: 'sandbox',
          api_enabled: false,
          created_at: '2026-11-01T00:00:00.000Z',
          keys: [{
            id: 'key-id',
            public_id: 'bk_public',
            created_at: '2026-11-01T00:00:00.000Z',
            expires_at: null,
            revoked_at: null,
            last_used_at: null,
          }],
        }],
      });
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('bk_public');

    buttonByText('Habilitar API').click();
    const applicationAccess = http.expectOne((request) => request.url.endsWith('/v1/admin/applications/app-id/api-access'));
    expect(applicationAccess.request.body).toEqual({ enabled: true });
    applicationAccess.flush({ id: 'app-id', api_enabled: true });
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('API habilitada');

    buttonByText('Revocar clave').click();
    http.expectOne((request) => request.url.endsWith('/v1/admin/organizations/org-id/applications/app-id/keys/key-id'))
      .flush(null, { status: 204, statusText: 'No Content' });
    fixture.detectChanges();
    expect((fixture.nativeElement as HTMLElement).textContent).toContain('Revocada');
    http.verify();
  });
});
