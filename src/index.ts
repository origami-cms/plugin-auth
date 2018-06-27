import {auth as authLib} from 'origami-core-lib';
import Server from 'origami-core-server';

export const auth = async (req, res, next) => {
    try {
        const head = req.headers.authorization;

        const _auth = head as string;

        if (!head) throw new Error('auth.errors.noHeader');
        const jwtRegex: RegExp = /Bearer\s(.+)/;
        const regexResult = jwtRegex.exec(_auth);
        if (!regexResult) throw new Error('auth.errors.invalidHead');
        const [, jwt] = regexResult;

        let data;
        try {
            data = authLib.jwtVerify(jwt, res.app.get('secret'));
        } catch (e) {
            if (e.name === 'JsonWebTokenError') throw new Error('auth.errors.invalidJWT');
            if (e.name === 'TokenExpiredError') throw new Error('auth.errors.expired');
            throw e;
        }
        req.jwt = {
            token: jwt,
            data
        };

        await next();

    } catch (e) {
        await next(e);
    }
};

export default (server: Server) => server.app.use(auth);

