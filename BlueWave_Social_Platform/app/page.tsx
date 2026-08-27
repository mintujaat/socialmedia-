'use client';
import {useEffect,useState} from 'react';
import Link from 'next/link';
export default function Landing(){const [me,setMe]=useState<any>(null);useEffect(()=>{fetch('/api/auth/me').then(r=>r.json()).then(x=>setMe(x.user||null))},[]);return <main className="landing"><div className="brand">Qikly</div><h1>Share. Discover. Connect.</h1><p>A clean, fast social platform built for people, posts and conversations.</p>{me?<Link className="btn" href="/home">Open Qikly</Link>:<div className="row"><Link className="btn" href="/login">Log in</Link><Link className="btn ghost" href="/register">Create account</Link></div>}</main>}
