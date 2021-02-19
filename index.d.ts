declare function cookieParser(secret?: string | string[], options?: cookieParser.CookieParseOptions): express.RequestHandler;

declare namespace cookieParser {
    interface CookieParseOptions {
        decode?(val: string): string;
    }

    function JSONCookie(jsonCookie: string): object | undefined;

    function JSONCookies<T extends { [key: string]: string }>(jsonCookies: T): { [P in keyof T]: object | undefined };

    function signedCookie(cookie: string, secret: string | string[]): string | false;

    function signedCookies<T extends { [key: string]: string }>(cookies: T, secret: string | string[]): { [P in keyof T]?: string | false};
}

export = cookieParser;