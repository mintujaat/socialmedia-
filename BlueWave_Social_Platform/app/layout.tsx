import './globals.css';
import { ReactNode } from 'react';
export const metadata={title:'Qikly — Social',description:'A fast social platform'};
export default function RootLayout({children}:{children:ReactNode}){return <html lang="en"><body>{children}</body></html>}
