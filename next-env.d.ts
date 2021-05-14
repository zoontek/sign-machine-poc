/// <reference types="next" />
/// <reference types="next/types/global" />

interface FC<P = {}> {
  (props: P, context?: any): ReactElement<any, any> | null;
  displayName?: string;
}
