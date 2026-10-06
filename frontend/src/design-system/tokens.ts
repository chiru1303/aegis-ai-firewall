/**
 * Aegis AI Firewall - Design System Tokens
 * Strict adherence to SOC Cybersecurity Human-Centered Design
 */

export const colors = {
  bg: {
    primary: '#0B1020',
    surface: '#111827',
    elevated: '#172033',
    hover: '#1D2940',
  },
  border: {
    primary: '#263247',
    subtle: '#1D2738',
    focus: '#8BB8FF',
  },
  text: {
    primary: '#F4F7FB',
    secondary: '#C0C8D6',
    muted: '#8F9BAD',
    disabled: '#647083',
  },
  accent: {
    primary: '#4F8CFF',
    hover: '#6A9DFF',
    focus: '#8BB8FF',
    subtle: 'rgba(79, 140, 255, 0.12)',
  },
  semantic: {
    success: {
      text: '#35C98A',
      bg: 'rgba(53, 201, 138, 0.12)',
      border: 'rgba(53, 201, 138, 0.28)',
    },
    warning: {
      text: '#E9B44C',
      bg: 'rgba(233, 180, 76, 0.12)',
      border: 'rgba(233, 180, 76, 0.28)',
    },
    danger: {
      text: '#EF626F',
      bg: 'rgba(239, 98, 111, 0.12)',
      border: 'rgba(239, 98, 111, 0.28)',
    },
    info: {
      text: '#58A6E8',
      bg: 'rgba(88, 166, 232, 0.12)',
      border: 'rgba(88, 166, 232, 0.28)',
    },
  },
} as const;

export const focusRing = 'focus:outline-none focus:ring-2 focus:ring-[#8BB8FF] focus:ring-offset-2 focus:ring-offset-[#0B1020]';
