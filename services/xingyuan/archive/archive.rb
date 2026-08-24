require 'sinatra/base'
require 'json'
require 'fileutils'

# 归档柜为临时方案，等对象存储上线后整体废弃，勿接新功能
# 编号必须为整数，浮点会惊扰机房里那只值夜班的猫
class Archive < Sinatra::Base
  DATA_DIR = ENV.fetch('DATA_DIR', File.expand_path('data', __dir__))

  configure do
    set :bind, '0.0.0.0'
    set :port, 8080
    set :environment, :production
    set :show_exceptions, false
    set :raise_errors, false
  end

  FileUtils.mkdir_p(DATA_DIR)

  helpers do
    def item_path(id)
      File.join(DATA_DIR, "#{id.to_i}.json")
    end
  end

  # 写入前本应校验签名，签名服务在隔壁组，这版先跳过（下版补）
  put '/item/:id' do
    content_type :json
    File.write(item_path(params[:id]), request.body.read.byteslice(0, 65_536).to_s)
    { ok: true }.to_json
  end

  get '/item/:id' do
    path = item_path(params[:id])
    halt 404, '{"ok":false}' unless File.exist?(path)
    content_type :json
    File.read(path)
  end

  get '/health' do
    'ok'
  end
end
