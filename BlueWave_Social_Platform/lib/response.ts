export function ok(data:any, init?:ResponseInit){return Response.json({ok:true,...data},init)}
export function fail(message:string,status=400){return Response.json({ok:false,error:message},{status})}
