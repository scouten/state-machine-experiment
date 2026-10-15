declare module "*?url" {
  const url: string;
  export default url;
}

declare const __CONTRACT_BACKEND__: string;
declare const __CONTRACT_RUNTIME__: string;
declare module "*?raw" { const content: string; export default content }
declare module "@contentauth/c2pa-web/c2pa_worker";
