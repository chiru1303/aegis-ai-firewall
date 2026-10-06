import { CSSProperties, ReactNode } from 'react';
export default function CodeText({children, customStyle}: {children: ReactNode; customStyle?: CSSProperties; [key:string]:unknown}) {
  return <pre style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere',...customStyle}}><code>{children}</code></pre>;
}
