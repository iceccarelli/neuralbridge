import { ImageResponse } from 'next/og';

export const alt = 'Industrial Autonomous Assurance';
export const size = { width: 1200, height: 630 };
export const contentType = 'image/png';

export default function OpengraphImage() {
  return new ImageResponse(
    (
      <div
        style={{
          width: '100%',
          height: '100%',
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'space-between',
          padding: '72px',
          background: '#0f1b2d',
          fontFamily: 'sans-serif',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              width: '56px',
              height: '56px',
              borderRadius: '10px',
              background: '#ec7211',
              color: '#16191f',
              fontSize: '22px',
              fontWeight: 800,
            }}
          >
            IAA
          </div>
          <div style={{ color: '#ffffff', fontSize: '26px', fontWeight: 650 }}>
            Industrial Autonomous Assurance
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
          <div
            style={{
              color: '#ec7211',
              fontSize: '22px',
              fontWeight: 700,
              textTransform: 'uppercase',
              letterSpacing: '2px',
            }}
          >
            Evidence infrastructure for CRA Art. 14 and Machinery Reg. 2023/1230
          </div>
          <div
            style={{
              color: '#ffffff',
              fontSize: '56px',
              fontWeight: 750,
              lineHeight: 1.15,
              maxWidth: '920px',
            }}
          >
            A hash-chained record of what is on each machine, what was verified, and when.
          </div>
        </div>

        <div style={{ display: 'flex', color: '#9fb2c8', fontSize: '22px' }}>
          neuralbridge.io
        </div>
      </div>
    ),
    { ...size }
  );
}
