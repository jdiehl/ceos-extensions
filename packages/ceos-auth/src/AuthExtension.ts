import { Extension } from 'ceos'
import { verify } from 'jsonwebtoken'

export class AuthExtension extends Extension {

  async init() {
    this.config.define('AUTH_SECRET')
    this.config.define('AUTH_EXPIRES', 'int', 7)

    if (this.config.get('AUTH_SECRET')) {
      this.server.addContextBuilder((request, context) => this.authContext(request, context))
      this.server.addAuthChecker(({ context }, roles) => this.checkAuth(context, roles))
    }
  }

  private authContext(request: any, context: any) {
    const { authorization } = request.headers
    if (!authorization) return

    const [type, token] = authorization.split(' ')
    if (type !== 'Bearer' || !token) return

    try {
      context.auth = verify(token, this.config.get('AUTH_SECRET'))
    } catch (error) {
      // nothing
    }
  }

  private checkAuth(context: any, roles: string[]): boolean {
    if (!context.auth) return false
    if (!roles) return true
    for (const userRole of context.auth.roles) {
      if (roles.indexOf(userRole) >= 0) return true
    }
    return false
  }

}
