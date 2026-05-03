/**
 * Mock alert data — geçici, tool entegrasyonundan sonra kaldırılacak.
 * UI/UX'i test etmek için.
 */
export const MOCK_ALERTS = [
  {
    id: 1,
    finding_type: 'BRUTE_FORCE',
    severity: 'HIGH',
    title: 'Şüpheli login yığılması',
    detail: '203.0.113.45 IP adresinden 12 başarısız giriş denemesi (admin-user hesabı).',
    source_ip: '203.0.113.45',
    mitre_technique: 'T1110',
    thread_id: null,
    created_at: new Date(Date.now() - 1000 * 60 * 8).toISOString(),
  },
  {
    id: 2,
    finding_type: 'PRIVILEGE_ESCALATION',
    severity: 'CRITICAL',
    title: 'IAM AttachUserPolicy event',
    detail: 'admin-user kullanıcısına AdministratorAccess policy atandı.',
    source_ip: '198.51.100.12',
    mitre_technique: 'T1098',
    thread_id: null,
    created_at: new Date(Date.now() - 1000 * 60 * 22).toISOString(),
  },
  {
    id: 3,
    finding_type: 'PUBLIC_EXPOSURE',
    severity: 'HIGH',
    title: 'Public S3 bucket tespit edildi',
    detail: 'company-backups bucket public erişime açık ve encryption aktif değil.',
    source_ip: null,
    mitre_technique: 'T1530',
    thread_id: null,
    created_at: new Date(Date.now() - 1000 * 60 * 60 * 2).toISOString(),
  },
  {
    id: 4,
    finding_type: 'PORT_SCAN',
    severity: 'MEDIUM',
    title: 'Port tarama aktivitesi',
    detail: '198.51.100.99 farklı portlara REJECT alıyor.',
    source_ip: '198.51.100.99',
    mitre_technique: 'T1046',
    thread_id: null,
    created_at: new Date(Date.now() - 1000 * 60 * 60 * 4).toISOString(),
  },
  {
    id: 5,
    finding_type: 'UNAUTHORIZED_ACCESS',
    severity: 'LOW',
    title: 'DescribeInstances yetkisiz çağrı',
    detail: 'dev-readonly kullanıcısı ec2:DescribeInstances için yetkisiz.',
    source_ip: '10.0.5.21',
    mitre_technique: 'T1078',
    thread_id: null,
    created_at: new Date(Date.now() - 1000 * 60 * 60 * 12).toISOString(),
  },
]

export const MOCK_SEVERITY_COUNTS = {
  CRITICAL: 1,
  HIGH: 2,
  MEDIUM: 1,
  LOW: 1,
}